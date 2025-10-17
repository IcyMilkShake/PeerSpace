const express = require('express');
const router = express.Router();

const authRoutes = require('./auth');
const userRoutes = require('./users');
const postRoutes = require('./posts');
const commentRoutes = require('./comments');
const notificationRoutes = require('./notifications');
const friendRequestRoutes = require('./friendRequests');
const communityRoutes = require('./communities');

router.use('/auth', authRoutes);
router.use('/api/users', userRoutes);
router.use('/api/posts', postRoutes);
router.use('/api/comments', commentRoutes);
router.use('/api/notifications', notificationRoutes);
router.use('/api/friend-request', friendRequestRoutes);
router.use('/api/communities', communityRoutes);

module.exports = router;