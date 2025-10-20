const express = require('express');
const router = express.Router();
const postController = require('../controllers/postController');
const commentController = require('../controllers/commentController');
const { isAuthenticated } = require('../middleware/auth');
const { postAttachmentUpload } = require('../config/multer');
const { Post } = require('../models');

router.get('/', postController.getAllPosts);
router.post('/', isAuthenticated, postAttachmentUpload.array('attachments', 15), postController.createPost);

router.get('/friends-recent', isAuthenticated, postController.getRecentFriendPosts);
router.get('/search', postController.searchPosts);
router.get('/:postId', postController.getPostById);
router.delete('/:postId', isAuthenticated, postController.deletePost);

router.post('/:postId/like', isAuthenticated, postController.likePost);
router.post('/:postId/voice-channel', isAuthenticated, postController.createVoiceChannel);
router.post('/:postId/report', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const { reasonType, reasonDetails } = req.body;
    const reporterId = req.user._id;

    if (!reasonType) {
      return res.status(400).json({ error: 'Report reason type is required.' });
    }
    if (reasonType.length > 200 || (reasonDetails && reasonDetails.length > 1000)) {
        return res.status(400).json({ error: 'Report reason or details too long.'});
    }

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    post.reports.push({
      reporter: reporterId,
      reasonType,
      reasonDetails: reasonDetails || '',
      reportedAt: new Date()
    });

    await post.save();
    res.json({ success: true, message: 'Post reported successfully.' });

  } catch (error) {
    console.error('Error reporting post:', error);
    res.status(500).json({ error: 'Failed to report post.' });
  }
});
router.post('/:postId/comments', isAuthenticated, commentController.createComment);
router.post('/:postId/vote', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const { optionIndex } = req.body;
    const userId = req.user._id;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }
    if (post.postType !== 'poll') {
      return res.status(400).json({ error: 'This post is not a poll.' });
    }
    if (optionIndex === undefined || optionIndex < 0 || optionIndex >= post.pollOptions.length) {
      return res.status(400).json({ error: 'Invalid poll option.' });
    }

    const existingVoteIndex = post.usersWhoVoted.findIndex(vote => vote.userId.equals(userId));

    if (existingVoteIndex > -1) {
      const previousVote = post.usersWhoVoted[existingVoteIndex];
      if (previousVote.optionIndex === optionIndex) {
        post.pollOptions[optionIndex].votes = Math.max(0, post.pollOptions[optionIndex].votes - 1);
        post.usersWhoVoted.splice(existingVoteIndex, 1);
      } else {
        if (post.pollOptions[previousVote.optionIndex]) {
          post.pollOptions[previousVote.optionIndex].votes = Math.max(0, post.pollOptions[previousVote.optionIndex].votes - 1);
        }
        post.usersWhoVoted[existingVoteIndex].optionIndex = optionIndex;
        post.pollOptions[optionIndex].votes += 1;
      }
    } else {
      post.pollOptions[optionIndex].votes += 1;
      post.usersWhoVoted.push({ userId, optionIndex });
    }

    await post.save();

    res.json({
      pollOptions: post.pollOptions.map(opt => ({
        option: opt.option,
        votes: opt.votes
      })),
      usersWhoVoted: post.usersWhoVoted
    });

  } catch (error) {
    console.error('Error voting in poll:', error);
    res.status(500).json({ error: 'Failed to cast vote.' });
  }
});

module.exports = router;