const express = require('express');
const router = express.Router();
const commentController = require('../controllers/commentController');
const { isAuthenticated } = require('../middleware/auth');

router.post('/:commentId/replies', isAuthenticated, commentController.createReply);
router.delete('/:commentId', isAuthenticated, commentController.deleteComment);
router.post('/:commentId/like', isAuthenticated, commentController.likeComment);
router.post('/:commentId/mark-answer', isAuthenticated, commentController.markAsAnswer);
router.post('/:commentId/unmark-answer', isAuthenticated, commentController.unmarkAsAnswer);
router.post('/:commentId/voice-channel', isAuthenticated, commentController.createVoiceChannel);
router.get('/:commentId/voice-channel', commentController.getVoiceChannelParticipants);
router.delete('/:commentId/voice-channel', isAuthenticated, commentController.deleteVoiceChannel);

module.exports = router;