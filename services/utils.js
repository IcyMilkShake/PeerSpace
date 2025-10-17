const { Comment } = require('../models');

async function populatePostDetails(post, currentUserId) {
    const allCommentsRaw = await Comment.find({ post: post._id })
        .populate('author', '_id username displayName profilePicture')
        .populate('voiceChannel')
        .sort({ createdAt: 1 });

    const buildCommentTree = (parentId) => {
        return allCommentsRaw
            .filter(comment => String(comment.parentComment) === String(parentId))
            .map(comment => {
                let replyingTo = null;
                if (comment.parentComment) {
                    const parentCommentObject = allCommentsRaw.find(c => String(c._id) === String(comment.parentComment));
                    if (parentCommentObject) {
                        replyingTo = { id: parentCommentObject.author._id, username: parentCommentObject.author.username };
                    } else {
                        replyingTo = { id: null, username: "Reply deleted" };
                    }
                }
                return {
                    id: comment._id, content: comment.content,
                    author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
                    likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                    createdAt: comment.createdAt.toISOString(), parentComment: comment.parentComment,
                    replyingTo: replyingTo, linkPreview: comment.linkPreview,
                    voiceChannel: comment.voiceChannel,
                    replies: buildCommentTree(comment._id)
                };
            });
    };

    const topLevelComments = allCommentsRaw
        .filter(comment => !comment.parentComment)
        .map(comment => ({
            id: comment._id, content: comment.content,
            author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
            likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
            createdAt: comment.createdAt.toISOString(), parentComment: null, replyingTo: null,
            linkPreview: comment.linkPreview,
            voiceChannel: comment.voiceChannel,
            replies: buildCommentTree(comment._id)
        }));

    return {
        id: post.id, // Use the virtual 'id'
        title: post.title,
        content: post.content,
        linkPreview: post.linkPreview,
        postType: post.postType,
        attachments: post.attachments,
        pollOptions: post.pollOptions ? post.pollOptions.map(opt => ({ option: opt.option, votes: opt.votes })) : [],
        voiceChannel: post.voiceChannel,
        community: post.community, // This will be serialized correctly by res.json
        author: {
            id: post.author.id, // Use the virtual 'id'
            username: post.author.username,
            displayName: post.author.displayName,
            photo: post.author.profilePicture.path || '/default-profile.png' // Correctly map to 'photo'
        },
        likes: post.likes.length,
        isLiked: currentUserId ? post.likes.includes(currentUserId) : false,
        createdAt: post.createdAt.toISOString(),
        comments: topLevelComments,
        usersWhoVoted: post.postType === 'poll' ? post.usersWhoVoted : undefined,
        answeredComment: post.answeredComment
    };
}

module.exports = {
    populatePostDetails,
};