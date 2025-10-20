const { Post, Comment, VoiceChannel } = require('../models');
const { processAndUploadFile, deleteCommentAndChildren } = require('../services/fileUploadService');
const { generateLinkPreview } = require('../services/linkPreviewService');
const { createNotificationsForMentions } = require('../services/notificationService');
const { populatePostDetails } = require('../services/utils');
const { scheduleVoiceChannelDeletion } = require('../services/voiceChannelService');
exports.getRecentFriendPosts = async (req, res) => {
    try {
        const currentUserId = req.user._id;
        const friends = req.user.friends;

        if (!friends || friends.length === 0) {
            return res.json([]);
        }

        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

        const recentFriendPosts = await Post.find({
            author: { $in: friends },
            createdAt: { $gte: threeDaysAgo }
        }).populate('author', 'username displayName profilePicture').populate('community', 'name _id').populate('voiceChannel');

        for (let i = recentFriendPosts.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [recentFriendPosts[i], recentFriendPosts[j]] = [recentFriendPosts[j], recentFriendPosts[i]];
        }

        const postsWithDetails = await Promise.all(
            recentFriendPosts.map(post => populatePostDetails(post, currentUserId))
        );

        res.json(postsWithDetails);

    } catch (error) {
        console.error('Error fetching recent friend posts:', error);
        res.status(500).json({ error: 'Failed to fetch recent friend posts' });
    }
};

exports.getAllPosts = async (req, res) => {
  try {
    const currentUserId = req.user ? req.user._id : null;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = req.query.filter || 'all';
    const communityId = req.query.communityId;

    let query = {};

    if (communityId && communityId !== 'null') {
        query.community = communityId;
    } else {
        query.community = { $eq: null };
    }

    if (filter !== 'all') {
      if (filter === 'normal') {
        query.$or = [{ postType: 'normal' }, { postType: { $exists: false } }];
      } else {
        query.postType = filter;
      }
    }

    const excludeIdsStr = req.query.exclude_ids || '';
    if (excludeIdsStr) {
        const excludedIds = excludeIdsStr.split(',').filter(id => mongoose.Types.ObjectId.isValid(id));
        if (excludedIds.length > 0) {
            query._id = { $nin: excludedIds };
        }
    }

    const totalPosts = await Post.countDocuments(query);

    const posts = await Post.find(query)
      .populate('author', 'username displayName profilePicture')
      .populate('community', 'name _id')
      .populate('voiceChannel')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const postsWithDetails = await Promise.all(
        posts.map(post => populatePostDetails(post, currentUserId))
    );

    res.json({
        posts: postsWithDetails,
        hasMore: (skip + posts.length) < totalPosts
    });

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
};

exports.createPost = async (req, res) => {
    try {
        const { title, content, postType, communityId } = req.body;
        let { pollOptions } = req.body;

        if (pollOptions) {
            pollOptions = JSON.parse(pollOptions);
        }

        if (!title) {
            return res.status(400).json({ error: 'Title is required' });
        }

        if (title.length > 75) {
            return res.status(400).json({ error: 'Title cannot exceed 75 characters.' });
        }

        if (content.length > 2500) {
            return res.status(400).json({ error: 'Content cannot exceed 2500 characters.' });
        }

        const newPostData = {
            title,
            content,
            author: req.user._id,
            postType: postType || 'normal',
            attachments: [],
            community: communityId || null
        };

        const linkPreview = await generateLinkPreview(content);
        if (linkPreview) {
            newPostData.linkPreview = linkPreview;
        }


        if (req.files && req.files.length > 0) {
            for (const file of req.files) {
                const attachment = await processAndUploadFile(file);
                if (attachment) {
                    newPostData.attachments.push(attachment);
                }
            }
        }

        if (postType === 'poll') {
            if (!pollOptions || !Array.isArray(pollOptions) || pollOptions.length < 2) {
                return res.status(400).json({ error: 'Polls require at least two options.' });
            }
            newPostData.pollOptions = pollOptions.map(opt => ({
                option: String(opt.option).trim(),
                votes: 0
            })).filter(opt => opt.option);

            if (newPostData.pollOptions.length < 2) {
                return res.status(400).json({ error: 'Polls require at least two valid options.' });
            }

            for (const opt of newPostData.pollOptions) {
                if (opt.option.length > 75) {
                    return res.status(400).json({ error: 'Poll option cannot exceed 75 characters.' });
                }
            }
        }

        const post = new Post(newPostData);
        await post.save();

        if (post.voiceChannel) {
            await VoiceChannel.findByIdAndUpdate(post.voiceChannel, { post: post._id });
        }

        await post.populate([
            { path: 'author', select: 'username displayName profilePicture' },
            { path: 'community', select: 'name _id' }
        ]);
        const io = req.app.get('socketio');
        await createNotificationsForMentions(content, post._id, null, req.user._id, io);

        const responsePost = {
            id: post._id,
            title: post.title,
            content: post.content,
            postType: post.postType,
            attachments: post.attachments,
            pollOptions: post.pollOptions,
            linkPreview: post.linkPreview,
            voiceChannel: post.voiceChannel,
            community: post.community,
            author: {
                id: post.author._id,
                username: post.author.username,
                displayName: post.author.displayName,
                photo: post.author.profilePicture.path || '/default-profile.png'
            },
            likes: [],
            isLiked: false,
            createdAt: post.createdAt.toISOString(),
            comments: []
        };

        io.emit('post:new', responsePost);
        res.status(201).json(responsePost);
    } catch (error) {
        console.error('Error creating post:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to create post' });
    }
};

exports.likePost = async (req, res) => {
    try {
        const { postId } = req.params;
        const userId = req.user._id;

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found.' });
        }

        const likedIndex = post.likes.indexOf(userId);
        if (likedIndex > -1) {
            post.likes.splice(likedIndex, 1);
        } else {
            post.likes.push(userId);
        }

        await post.save();

        const io = req.app.get('socketio');
        io.emit('post:like', { postId: post._id, likesCount: post.likes.length });

        res.json({
            likesCount: post.likes.length,
            isLiked: post.likes.includes(userId)
        });

    } catch (error) {
        console.error('Error liking/unliking post:', error);
        res.status(500).json({ error: 'Failed to update post like status.' });
    }
};

exports.createVoiceChannel = async (req, res) => {
    try {
        const { postId } = req.params;
        const { name } = req.body;
        const userId = req.user._id;
        console.log(req.body)
        // Check if user already has an active voice channel
        const existingChannel = await VoiceChannel.findOne({ creator: userId });
        if (existingChannel) {
            return res.status(409).json({
                error: 'You have already created a voice channel.',
                channelId: existingChannel._id,
                postId: existingChannel.post,
                commentId: existingChannel.comment
            });
        }
        console.log(postId, name, userId)
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found.' });
        }
        if (post.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to create a voice channel on this post.' });
        }
        if (post.voiceChannel) {
            return res.status(409).json({ error: 'This post already has a voice channel.' });
        }

        const voiceChannel = new VoiceChannel({
            post: postId,
            name: name || 'Voice Channel',
            creator: userId,
            participants: []
        });
        await voiceChannel.save();

        post.voiceChannel = voiceChannel._id;
        await post.save();

        const io = req.app.get('socketio');
        scheduleVoiceChannelDeletion(voiceChannel._id, io);

        io.emit('voice-channel-created', {
            itemType: 'post',
            itemId: postId,
            voiceChannel: voiceChannel
        });

        res.status(201).json({ success: true, voiceChannelId: voiceChannel._id });

    } catch (error) {
        console.error('Error creating voice channel for post:', error);
        res.status(500).json({ error: 'Failed to create voice channel.' });
    }
};

exports.searchPosts = async (req, res) => {
    try {
        const { q } = req.query;

        if (!q) {
            return res.json([]);
        }

        const posts = await Post.find({
            $or: [
                { title: { $regex: q, $options: 'i' } },
                { content: { $regex: q, $options: 'i' } }
            ]
        })
            .sort({ createdAt: -1 })
            .limit(10)
            .select('title content');

        const results = posts.map(post => ({
            id: post._id,
            title: post.title,
            content: post.content.substring(0, 100) + (post.content.length > 100 ? '...' : '')
        }));

        res.json(results);

    } catch (error) {
        console.error('Error searching posts:', error);
        res.status(500).json({ error: 'Failed to search posts' });
    }
};

exports.getPostById = async (req, res) => {
    try {
        const currentUserId = req.user ? req.user._id : null;
        const post = await Post.findById(req.params.postId)
            .populate('author', 'username displayName profilePicture')
            .populate('community', 'name _id')
            .populate('voiceChannel');

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const postWithDetails = await populatePostDetails(post, currentUserId);

        res.json(postWithDetails);
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ error: 'Failed to fetch post' });
    }
};

exports.deletePost = async (req, res) => {
    try {
        const { postId } = req.params;
        const userId = req.user._id;

        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found.' });
        }

        if (post.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'User not authorized to delete this post.' });
        }

        if (post.voiceChannel) {
            await VoiceChannel.findByIdAndDelete(post.voiceChannel);
        }

        const comments = await Comment.find({ post: postId });
        for (const comment of comments) {
            await deleteCommentAndChildren(comment._id);
        }

        await Post.findByIdAndDelete(postId);

        const io = req.app.get('socketio');
        io.emit('post:delete', { postId });

        res.json({ success: true, message: 'Post and associated comments deleted successfully.' });

    } catch (error) {
        console.error('Error deleting post:', error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ error: 'Invalid Post ID format.' });
        }
        res.status(500).json({ error: 'Failed to delete post.' });
    }
};