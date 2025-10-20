const { Post, Comment, User, VoiceChannel } = require('../models');
const { generateLinkPreview } = require('../services/linkPreviewService');
const { createNotificationsForMentions } = require('../services/notificationService');
const { awardCredibility, revokeCredibility } = require('../services/credibilityService');
const { deleteCommentAndChildren } = require('../services/fileUploadService');
const { scheduleVoiceChannelDeletion } = require('../services/voiceChannelService');
exports.createComment = async (req, res) => {
    try {
        const { postId } = req.params;
        const { content } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Content is required' });
        }

        if (content.length > 1000) {
            return res.status(400).json({ error: 'Comment cannot exceed 1000 characters.' });
        }

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const comment = new Comment({
            content,
            author: req.user._id,
            post: postId
        });

        const linkPreview = await generateLinkPreview(content);
        if (linkPreview) {
            comment.linkPreview = linkPreview;
        }

        await comment.save();

        if (comment.voiceChannel) {
            await VoiceChannel.findByIdAndUpdate(comment.voiceChannel, { comment: comment._id });
        }

        await comment.populate('author', 'username displayName profilePicture');
        const io = req.app.get('socketio');
        await createNotificationsForMentions(content, postId, comment._id, req.user._id, io);

        const responseComment = {
            id: comment._id,
            content: comment.content,
            author: {
                id: comment.author._id,
                username: comment.author.username,
                displayName: comment.author.displayName,
                photo: comment.author.profilePicture.path || '/default-profile.png'
            },
            likes: 0,
            isLiked: false,
            createdAt: comment.createdAt.toISOString(),
            parentComment: null,
            replyingTo: null,
            linkPreview: comment.linkPreview,
            voiceChannel: comment.voiceChannel,
            replies: [],
            post: postId
        };

        io.to(`post-${postId}`).emit('comment:new', responseComment);

        res.json(responseComment);
    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Failed to create comment' });
    }
};

exports.createReply = async (req, res) => {
    try {
        const { commentId } = req.params;
        const { content } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Content is required for a reply.' });
        }

        if (content.length > 1000) {
            return res.status(400).json({ error: 'Reply cannot exceed 1000 characters.' });
        }

        const parentComment = await Comment.findById(commentId).populate('author', 'id username');
        if (!parentComment) {
            return res.status(404).json({ error: 'Parent comment not found.' });
        }

        const reply = new Comment({
            content,
            author: req.user._id,
            post: parentComment.post,
            parentComment: commentId
        });

        const linkPreview = await generateLinkPreview(content);
        if (linkPreview) {
            reply.linkPreview = linkPreview;
        }

        await reply.save();

        if (reply.voiceChannel) {
            await VoiceChannel.findByIdAndUpdate(reply.voiceChannel, { comment: reply._id });
        }

        await reply.populate('author', 'username displayName profilePicture');
        const io = req.app.get('socketio');
        await createNotificationsForMentions(content, parentComment.post, reply._id, req.user._id, io);

        const responseReply = {
            id: reply._id,
            content: reply.content,
            author: {
                id: reply.author._id,
                username: reply.author.username,
                displayName: reply.author.displayName,
                photo: reply.author.profilePicture.path || '/default-profile.png'
            },
            likes: 0,
            isLiked: false,
            createdAt: reply.createdAt.toISOString(),
            parentComment: reply.parentComment,
            replyingTo: {
                id: parentComment.author._id,
                username: parentComment.author.username
            },
            linkPreview: reply.linkPreview,
            voiceChannel: reply.voiceChannel,
            replies: [],
            post: parentComment.post
        };

        io.to(`post-${parentComment.post}`).emit('reply:new', responseReply);

        res.status(201).json(responseReply);
    } catch (error) {
        console.error('Error creating reply:', error);
        res.status(500).json({ error: 'Failed to create reply.' });
    }
};

exports.deleteComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user._id;

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        if (comment.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'User not authorized to delete this comment.' });
        }

        const postId = comment.post;
        const post = await Post.findById(postId);
        const parentCommentId = comment.parentComment;

        if (comment.parentComment === null) {
            await deleteCommentAndChildren(commentId);
        } else {
            await Comment.findByIdAndDelete(commentId);
        }

        if (post.answeredComment && post.answeredComment.toString() === commentId) {
            post.answeredComment = null;
            await post.save();

            const commentAuthor = await User.findById(comment.author);
            if (commentAuthor && comment.author.toString() !== post.author.toString() && comment.credibilityAwardedForAnswer) {
                await revokeCredibility(commentAuthor, 10);
            }
        }
        const io = req.app.get('socketio');
        io.emit('comment:delete', { commentId, postId, parentCommentId });

        res.json({ success: true, message: 'Comment deleted successfully.' });

    } catch (error) {
        console.error('Error deleting comment:', error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ error: 'Invalid Comment ID format.' });
        }
        res.status(500).json({ error: 'Failed to delete comment.' });
    }
};

exports.likeComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user._id;

        const comment = await Comment.findById(commentId).populate('author');
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        const wasLiked = comment.likes.includes(userId);
        const originalLikeCount = comment.likes.length;

        if (wasLiked) {
            comment.likes.pull(userId);
        } else {
            comment.likes.push(userId);
        }

        await comment.save();
        const newLikeCount = comment.likes.length;

        // Credibility logic for likes
        if (newLikeCount >= 10 && !comment.credibilityAwardedForLikes) {
            await awardCredibility(comment.author, 1, comment);
        } else if (originalLikeCount >= 10 && newLikeCount < 10 && comment.credibilityAwardedForLikes) {
            await revokeCredibility(comment.author, 1, comment);
        }

        const io = req.app.get('socketio');
        io.emit('comment:like', { commentId: comment._id, postId: comment.post, likesCount: newLikeCount });

        res.json({
            likesCount: newLikeCount,
            isLiked: !wasLiked
        });

    } catch (error) {
        console.error('Error liking/unliking comment:', error);
        res.status(500).json({ error: 'Failed to update comment like status.' });
    }
};

exports.markAsAnswer = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user._id;

        const comment = await Comment.findById(commentId).populate('author');
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        const post = await Post.findById(comment.post).populate('author');
        if (!post) {
            return res.status(404).json({ error: 'Associated post not found.' });
        }

        if (post.postType !== 'question') {
            return res.status(400).json({ error: 'This feature is only available for question posts.' });
        }

        if (post.author._id.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to mark an answer for this post.' });
        }

        if (post.answeredComment && post.answeredComment.equals(commentId)) {
            // If the same comment is marked again, do nothing.
            return res.json({ success: true, answeredComment: commentId });
        }

        post.answeredComment = commentId;

        await post.save();

        // Award credibility to the author of the answer, only if they are not the post author
        if (comment.author._id.toString() !== post.author._id.toString()) {
            const awarded = await awardCredibility(comment.author, 10);
            if (awarded) {
                comment.credibilityAwardedForAnswer = true;
                await comment.save();
            }
        }

        const io = req.app.get('socketio');
        io.to(`post-${post._id}`).emit('post:answer_marked', { postId: post._id, answeredCommentId: commentId });

        res.json({ success: true, answeredComment: commentId });

    } catch (error) {
        console.error('Error marking comment as answer:', error);
        res.status(500).json({ error: 'Failed to mark comment as answer.' });
    }
};

exports.unmarkAsAnswer = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user._id;

        const comment = await Comment.findById(commentId).populate('author');
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        const post = await Post.findById(comment.post);
        if (!post) {
            return res.status(404).json({ error: 'Associated post not found.' });
        }

        if (post.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to unmark an answer for this post.' });
        }

        if (post.answeredComment && post.answeredComment.toString() === commentId) {
            post.answeredComment = null;
            await post.save();

            // Revoke credibility only if it was previously awarded for the answer
            if (comment.credibilityAwardedForAnswer) {
                if (comment.author._id.toString() !== post.author.toString()) {
                    await revokeCredibility(comment.author, 10);
                }
                comment.credibilityAwardedForAnswer = false;
                await comment.save();
            }
        } else {
            return res.status(400).json({ error: 'This comment is not the marked answer.' });
        }

        const io = req.app.get('socketio');
        io.to(`post-${post._id}`).emit('post:answer_unmarked', { postId: post._id });

        res.json({ success: true, answeredComment: null });

    } catch (error) {
        console.error('Error unmarking comment as answer:', error);
        res.status(500).json({ error: 'Failed to unmark comment as answer.' });
    }
};

exports.createVoiceChannel = async (req, res) => {
    try {
        const { commentId } = req.params;
        const { name } = req.body;
        const userId = req.user._id;

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

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }
        if (comment.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to create a voice channel on this comment.' });
        }

        if (comment.voiceChannel) {
            return res.status(409).json({ error: 'This comment already has a voice channel.' });
        }

        const voiceChannel = new VoiceChannel({
            post: comment.post,
            comment: commentId,
            name: name || 'Voice Channel',
            creator: userId,
            participants: []
        });
        await voiceChannel.save();
        console.log("saved?")
        comment.voiceChannel = voiceChannel._id;
        await comment.save();

        const io = req.app.get('socketio');
        scheduleVoiceChannelDeletion(voiceChannel._id, io);

        io.emit('voice-channel-created', {
            itemType: 'comment',
            itemId: commentId,
            postId: comment.post,
            voiceChannel: voiceChannel
        });

        res.status(201).json({ success: true, voiceChannelId: voiceChannel._id });

    } catch (error) {
        console.error('Error creating voice channel for comment:', error);
        res.status(500).json({ error: 'Failed to create voice channel.' });
    }
};

exports.getVoiceChannelParticipants = async (req, res) => {
    try {
        const { commentId } = req.params;
        const comment = await Comment.findById(commentId).populate({
            path: 'voiceChannel',
            populate: {
                path: 'participants',
                select: 'displayName profilePicture.path'
            }
        });

        if (!comment || !comment.voiceChannel) {
            return res.status(404).json({ error: 'Voice channel not found for this comment.' });
        }

        res.json(comment.voiceChannel.participants);

    } catch (error) {
        console.error('Error fetching voice channel participants for comment:', error);
        res.status(500).json({ error: 'Failed to fetch participants.' });
    }
};

exports.deleteVoiceChannel = async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.user._id;

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        if (comment.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to delete this voice channel.' });
        }

        if (!comment.voiceChannel) {
            return res.status(404).json({ error: 'This comment does not have a voice channel.' });
        }

        await VoiceChannel.findByIdAndDelete(comment.voiceChannel);
        comment.voiceChannel = null;
        await comment.save();

        const io = req.app.get('socketio');
        io.emit('voice-channel-deleted', {
            itemType: 'comment',
            itemId: commentId,
            postId: comment.post
        });

        res.json({ success: true, message: 'Voice channel deleted successfully.' });

    } catch (error) {
        console.error('Error deleting voice channel for comment:', error);
        res.status(500).json({ error: 'Failed to delete voice channel.' });
    }
};

exports.reportComment = async (req, res) => {
    try {
        const { commentId } = req.params;
        const { reasonType, reasonDetails } = req.body;
        const reporterId = req.user._id;

        if (!reasonType) {
            return res.status(400).json({ error: 'Report reason type is required.' });
        }
        if (reasonType.length > 200 || (reasonDetails && reasonDetails.length > 1000)) {
            return res.status(400).json({ error: 'Report reason or details too long.' });
        }

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        comment.reports.push({
            reporter: reporterId,
            reasonType,
            reasonDetails: reasonDetails || '',
            reportedAt: new Date()
        });

        await comment.save();
        res.json({ success: true, message: 'Comment reported successfully.' });

    } catch (error) {
        console.error('Error reporting comment:', error);
        res.status(500).json({ error: 'Failed to report comment.' });
    }
};