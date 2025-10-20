const express = require('express');
const router = express.Router();

const authRoutes = require('./auth');
const userRoutes = require('./user');
const postRoutes = require('./posts');
const commentRoutes = require('./comments');
const notificationRoutes = require('./notifications');
const friendRequestRoutes = require('./friendRequests');
const communityRoutes = require('./communities');

router.use('/auth', authRoutes);
router.use('/user', userRoutes);
router.use('/posts', postRoutes);
router.use('/comments', commentRoutes);
router.use('/notifications', notificationRoutes);
router.use('/friend-request', friendRequestRoutes);
router.use('/communities', communityRoutes);

module.exports = router;