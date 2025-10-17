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

module.exports = router;