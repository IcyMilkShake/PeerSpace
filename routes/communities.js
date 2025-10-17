const express = require('express');
const router = express.Router();
const communityController = require('../controllers/communityController');
const { isAuthenticated } = require('../middleware/auth');
const { upload } = require('../config/multer');

router.get('/', communityController.getAllCommunities);
router.post('/', isAuthenticated, upload.fields([{ name: 'profilePicture', maxCount: 1 }, { name: 'bannerPicture', maxCount: 1 }]), communityController.createCommunity);
router.get('/:communityId', communityController.getCommunityById);
router.put('/:communityId', isAuthenticated, upload.fields([{ name: 'profilePicture', maxCount: 1 }, { name: 'bannerPicture', maxCount: 1 }]), communityController.updateCommunity);
router.delete('/:communityId', isAuthenticated, communityController.deleteCommunity);
router.post('/:communityId/join', isAuthenticated, communityController.joinCommunity);
router.post('/:communityId/leave', isAuthenticated, communityController.leaveCommunity);

module.exports = router;