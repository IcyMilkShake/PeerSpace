const { User, FriendRequest } = require('../models');

exports.sendFriendRequest = async (req, res) => {
    const { recipientId } = req.body;
    const requesterId = req.user._id;

    if (requesterId.equals(recipientId)) {
        return res.status(400).json({ error: "You cannot send a friend request to yourself." });
    }

    try {
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { requester: requesterId, recipient: recipientId },
                { requester: recipientId, recipient: requesterId }
            ]
        });

        if (existingRequest) {
            return res.status(400).json({ error: "A friend request already exists between you and this user." });
        }

        const recipient = await User.findById(recipientId);
        if (!recipient) {
            return res.status(404).json({ error: 'Recipient not found' });
        }

        const areFriends = recipient.friends.includes(requesterId);
        if (areFriends) {
            return res.status(400).json({ error: 'You are already friends with this user.' });
        }

        const newRequest = new FriendRequest({
            requester: requesterId,
            recipient: recipientId
        });

        await newRequest.save();
        res.status(201).json({ success: true, message: 'Friend request sent.' });

    } catch (error) {
        console.error('Error sending friend request:', error);
        res.status(500).json({ error: 'Failed to send friend request.' });
    }
};

exports.getPendingFriendRequests = async (req, res) => {
    try {
        const requests = await FriendRequest.find({ recipient: req.user._id, status: 'pending' })
            .populate('requester', 'username displayName profilePicture');
        res.json(requests);
    } catch (error) {
        console.error('Error fetching friend requests:', error);
        res.status(500).json({ error: 'Failed to fetch friend requests.' });
    }
};

exports.getSentFriendRequests = async (req, res) => {
    try {
        const requests = await FriendRequest.find({ requester: req.user._id, status: 'pending' })
            .populate('recipient', 'username displayName profilePicture');
        res.json(requests);
    } catch (error) {
        console.error('Error fetching sent friend requests:', error);
        res.status(500).json({ error: 'Failed to fetch sent friend requests.' });
    }
};

exports.acceptFriendRequest = async (req, res) => {
    try {
        const { requestId } = req.params;
        const recipientId = req.user._id;

        const request = await FriendRequest.findById(requestId);

        if (!request || !request.recipient.equals(recipientId) || request.status !== 'pending') {
            return res.status(404).json({ error: 'Friend request not found or you are not authorized to accept it.' });
        }

        const requesterId = request.requester;

        await User.findByIdAndUpdate(requesterId, { $addToSet: { friends: recipientId } });
        await User.findByIdAndUpdate(recipientId, { $addToSet: { friends: requesterId } });

        await FriendRequest.findByIdAndDelete(requestId);

        res.json({ success: true, message: 'Friend request accepted.' });

    } catch (error) {
        console.error('Error accepting friend request:', error);
        res.status(500).json({ error: 'Failed to accept friend request.' });
    }
};

exports.declineFriendRequest = async (req, res) => {
    try {
        const { requestId } = req.params;
        const userId = req.user._id;

        const request = await FriendRequest.findById(requestId);

        if (!request || (!request.recipient.equals(userId) && !request.requester.equals(userId)) || request.status !== 'pending') {
            return res.status(404).json({ error: 'Friend request not found or you are not authorized to decline it.' });
        }

        await FriendRequest.findByIdAndDelete(requestId);

        res.json({ success: true, message: 'Friend request declined.' });

    } catch (error) {
        console.error('Error declining friend request:', error);
        res.status(500).json({ error: 'Failed to decline friend request.' });
    }
};

exports.getFriends = async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('friends', 'username displayName profilePicture');
        res.json(user.friends);
    } catch (error) {
        console.error('Error fetching friends list:', error);
        res.status(500).json({ error: 'Failed to fetch friends list.' });
    }
};

exports.unfriend = async (req, res) => {
    try {
        const { friendId } = req.params;
        const currentUserId = req.user._id;

        // Remove friend from current user's list
        await User.findByIdAndUpdate(currentUserId, { $pull: { friends: friendId } });

        // Remove current user from friend's list
        await User.findByIdAndUpdate(friendId, { $pull: { friends: currentUserId } });

        res.json({ success: true, message: 'Friend removed.' });

    } catch (error) {
        console.error('Error removing friend:', error);
        res.status(500).json({ error: 'Failed to remove friend.' });
    }
};

exports.cancelFriendRequest = async (req, res) => {
    try {
        const { recipientId } = req.params;
        const requesterId = req.user._id;

        const result = await FriendRequest.findOneAndDelete({
            requester: requesterId,
            recipient: recipientId,
            status: 'pending'
        });

        if (!result) {
            return res.status(404).json({ error: 'Friend request not found or already handled.' });
        }

        res.json({ success: true, message: 'Friend request cancelled.' });

    } catch (error) {
        console.error('Error cancelling friend request:', error);
        res.status(500).json({ error: 'Failed to cancel friend request.' });
    }
};

exports.getFriendStatus = async (req, res) => {
    try {
        const { userId } = req.params;
        const currentUserId = req.user._id;

        if (currentUserId.equals(userId)) {
            return res.json({ status: 'self' });
        }

        const areFriends = req.user.friends.includes(userId);
        if (areFriends) {
            return res.json({ status: 'friends' });
        }

        const pendingRequest = await FriendRequest.findOne({
            $or: [
                { requester: currentUserId, recipient: userId },
                { requester: userId, recipient: currentUserId }
            ],
            status: 'pending'
        });

        if (pendingRequest) {
            if (pendingRequest.requester.equals(currentUserId)) {
                return res.json({ status: 'sent' });
            } else {
                return res.json({ status: 'received' });
            }
        }

        res.json({ status: 'none' });

    } catch (error) {
        console.error('Error fetching friend status:', error);
        res.status(500).json({ error: 'Failed to fetch friend status.' });
    }
};