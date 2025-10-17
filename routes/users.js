const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { isAuthenticated } = require('../middleware/auth');
const { upload } = require('../config/multer');

router.get('/', isAuthenticated, userController.getCurrentUser);
router.get('/search', userController.searchUsers);
router.get('/:userId', userController.getUserProfile);
router.get('/by-username/:username', userController.getUserByUsername);
router.get('/:userId/content', userController.getUserContent);

router.put('/description', isAuthenticated, userController.updateUserDescription);
router.put('/displayName', isAuthenticated, userController.updateUserDisplayName);
router.put('/username', isAuthenticated, userController.updateUsername);
router.put('/theme', isAuthenticated, userController.updateUserTheme);
router.put('/audio-settings', isAuthenticated, userController.updateAudioSettings);

router.post('/send-verification-email', isAuthenticated, userController.sendVerificationEmail);
router.get('/verify-email/:token', userController.verifyEmail);
router.post('/hide-credibility-notification', isAuthenticated, userController.hideCredibilityNotification);

router.post('/profile-picture', isAuthenticated, upload.single('profilePicture'), userController.uploadProfilePicture);
router.post('/banner-picture', isAuthenticated, upload.single('bannerPicture'), userController.uploadBannerPicture);

module.exports = router;