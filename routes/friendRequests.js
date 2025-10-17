const express = require('express');
const router = express.Router();
const friendRequestController = require('../controllers/friendRequestController');
const { isAuthenticated } = require('../middleware/auth');

router.post('/', isAuthenticated, friendRequestController.sendFriendRequest);
router.get('/', isAuthenticated, friendRequestController.getPendingFriendRequests);
router.get('/sent', isAuthenticated, friendRequestController.getSentFriendRequests);
router.put('/:requestId/accept', isAuthenticated, friendRequestController.acceptFriendRequest);
router.put('/:requestId/decline', isAuthenticated, friendRequestController.declineFriendRequest);
router.delete('/:recipientId', isAuthenticated, friendRequestController.cancelFriendRequest);

router.get('/status/:userId', isAuthenticated, friendRequestController.getFriendStatus);
router.get('/friends', isAuthenticated, friendRequestController.getFriends);
router.delete('/friends/:friendId', isAuthenticated, friendRequestController.unfriend);

module.exports = router;