const { Notification, FriendRequest } = require('../models');

exports.getNotifications = async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.user._id })
            .populate('sender', 'displayName')
            .populate('post', 'title')
            .sort({ createdAt: -1 });

        const responseNotifications = notifications
            .filter(n => n.post)
            .map(n => {
                let message = '';
                let link = `/#/post/${n.post._id}`;

                switch (n.type) {
                    case 'mention':
                        if (n.sender) {
                            message = `<strong>${n.sender.displayName}</strong> mentioned you in <strong>${n.post.title}</strong>.`;
                        }
                        if (n.comment) {
                            link += `#comment-${n.comment}`;
                        }
                        break;
                    case 'voice_channel_deleted':
                        message = `Your voice channel in <strong>${n.post.title}</strong> was removed after being left unattended.`;
                        break;
                    default:
                        return null;
                }

                return {
                    _id: n._id,
                    message: message,
                    link: link,
                    read: n.read,
                    createdAt: n.createdAt
                };
            }).filter(Boolean);

        res.json(responseNotifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
};

exports.getNotificationCounts = async (req, res) => {
    try {
        const unreadNotifications = await Notification.countDocuments({ user: req.user._id, read: false });
        const pendingFriendRequests = await FriendRequest.countDocuments({ recipient: req.user._id, status: 'pending' });

        res.json({
            unreadNotifications,
            pendingFriendRequests
        });
    } catch (error) {
        console.error('Error fetching notification counts:', error);
        res.status(500).json({ error: 'Failed to fetch notification counts' });
    }
};

exports.getUnreadNotificationCount = async (req, res) => {
    try {
        const count = await Notification.countDocuments({ user: req.user._id, read: false });
        res.json({ count });
    } catch (error) {
        console.error('Error fetching unread notification count:', error);
        res.status(500).json({ error: 'Failed to fetch unread notification count' });
    }
};

exports.markNotificationAsRead = async (req, res) => {
    try {
        const { notificationId } = req.params;
        const userId = req.user._id;

        const notification = await Notification.findOneAndUpdate(
            { _id: notificationId, user: userId },
            { read: true },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        const unreadNotifications = await Notification.countDocuments({ user: userId, read: false });
        const pendingFriendRequests = await FriendRequest.countDocuments({ recipient: userId, status: 'pending' });

        res.json({
            success: true,
            unreadNotifications,
            pendingFriendRequests
        });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ error: 'Failed to mark notification as read' });
    }
};

exports.deleteNotification = async (req, res) => {
    try {
        const { notificationId } = req.params;
        const userId = req.user._id;

        const result = await Notification.deleteOne({ _id: notificationId, user: userId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Notification not found or you do not have permission to delete it.' });
        }

        res.json({ success: true, message: 'Notification deleted successfully.' });

    } catch (error) {
        console.error('Error deleting notification:', error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ error: 'Invalid Notification ID format.' });
        }
        res.status(500).json({ error: 'Failed to delete notification.' });
    }
};

exports.deleteOldReadNotifications = async (req, res) => {
    try {
        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

        await Notification.deleteMany({
            user: req.user._id,
            read: true,
            createdAt: { $lt: threeDaysAgo }
        });

        res.status(200).json({ success: true, message: 'Old read notifications deleted.' });
    } catch (error) {
        console.error('Error deleting old read notifications:', error);
        res.status(500).json({ error: 'Failed to delete old read notifications.' });
    }
};