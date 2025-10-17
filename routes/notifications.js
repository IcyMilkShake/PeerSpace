const express = require('express');
const router = express.Router();
const notificationController = require('../controllers/notificationController');
const { isAuthenticated } = require('../middleware/auth');

router.get('/', isAuthenticated, notificationController.getNotifications);
router.get('/counts', isAuthenticated, notificationController.getNotificationCounts);
router.get('/unread-count', isAuthenticated, notificationController.getUnreadNotificationCount);
router.post('/:notificationId/read', isAuthenticated, notificationController.markNotificationAsRead);
router.delete('/:notificationId', isAuthenticated, notificationController.deleteNotification);

module.exports = router;