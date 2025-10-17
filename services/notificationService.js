const { User, Notification, FriendRequest } = require('../models');

// A helper function to emit notification count updates to a user
async function emitNotificationCountUpdate(userId, io) {
    try {
        if (!userId || !io) return;

        const unreadNotifications = await Notification.countDocuments({ user: userId, read: false });
        const pendingFriendRequests = await FriendRequest.countDocuments({ recipient: userId, status: 'pending' });

        const sockets = await io.fetchSockets();
        for (const socket of sockets) {
            if (socket.userId && socket.userId.toString() === userId.toString()) {
                socket.emit('notification_count_update', {
                    unreadNotifications,
                    pendingFriendRequests
                });
            }
        }
    } catch (error) {
        console.error(`Error emitting notification count update for user ${userId}:`, error);
    }
}

// Creates notifications for any users mentioned in a post or comment.
async function createNotificationsForMentions(text, postId, commentId, senderId, io) {
    const mentionRegex = /@(\w+)/g;
    const mentions = text.match(mentionRegex);

    if (mentions) {
        const mentionedUsernames = [...new Set(mentions.map(mention => mention.substring(1).toLowerCase()))];

        for (const username of mentionedUsernames) {
            const user = await User.findOne({ username: username });
            if (user && user._id.toString() !== senderId.toString()) {
                const notification = new Notification({
                    user: user._id,
                    sender: senderId,
                    type: 'mention',
                    post: postId,
                    comment: commentId,
                });
                await notification.save();
                await emitNotificationCountUpdate(user._id, io);
            }
        }
    }
}

module.exports = {
    emitNotificationCountUpdate,
    createNotificationsForMentions,
};