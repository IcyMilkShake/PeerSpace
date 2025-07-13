const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const https = require('https');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
require('dotenv').config();

const { User, Post, Comment } = require('./schema');

const app = express();
const PORT = process.env.PORT || 3000;

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads', 'profile_pics');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

AWS.config.update({
  region: 'ap-southeast-7',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const s3 = new AWS.S3();
const BUCKET_NAME = 'peerspace-database';

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/PeerSpace', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Multer configuration for profile picture uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueId = uuidv4();
    cb(null, `${uniqueId}.png`);
  }
});

// Recursive helper function to delete a comment and all its children
async function deleteCommentAndChildren(commentId) {
  // Find and delete children first
  const children = await Comment.find({ parentComment: commentId });
  for (const child of children) {
    await deleteCommentAndChildren(child._id); // Recursive call
  }
  // After all children are deleted, delete the comment itself
  await Comment.findByIdAndDelete(commentId);
}


const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image! Please upload only images.'), false);
    }
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Session configuration with MongoDB store
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/PeerSpace',
    touchAfter: 24 * 3600
  }),
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Helper function to download and save profile picture from Google
async function downloadProfilePicture(url, filename) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(path.join(uploadsDir, filename));
    
    https.get(url, (response) => {
      response.pipe(file);
      file.on('finish', () => {
        file.close();
        resolve(filename);
      });
    }).on('error', (err) => {
      fs.unlink(path.join(uploadsDir, filename), () => {}); // Delete the file on error
      reject(err);
    });
  });
}

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });

    const profilePictureUrl = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
    
    if (user) {
      // Update last login
      user.lastLogin = new Date();
      
      // Only update profile picture if user doesn't have a custom one
      // (i.e., if the current profile picture is from Google or is null)
      const hasCustomProfilePic = user.profilePicture.path && 
                                  user.profilePicture.path.startsWith('/uploads/profile_pics/');
      
      if (!hasCustomProfilePic && profilePictureUrl) {
        try {
          const filename = `google_${uuidv4()}.png`;
          await downloadProfilePicture(profilePictureUrl, filename);
          
          // Delete old Google profile picture if it exists
          if (user.profilePicture.path && user.profilePicture.path.includes('google_')) {
            const oldFilePath = path.join(__dirname, user.profilePicture.path);
            if (fs.existsSync(oldFilePath)) {
              fs.unlinkSync(oldFilePath);
            }
          }
          
          user.profilePicture = {
            path: `/uploads/profile_pics/${filename}`,
            contentType: 'image/png'
          };
        } catch (error) {
          console.error('Error downloading profile picture:', error);
          // Keep existing profile picture on error
        }
      }
      
      await user.save();
      return done(null, user);
    } else {
      // New user - download Google profile picture
      let profilePicturePath = null;
      
      if (profilePictureUrl) {
        try {
          const filename = `google_${uuidv4()}.png`;
          await downloadProfilePicture(profilePictureUrl, filename);
          profilePicturePath = `/uploads/profile_pics/${filename}`;
        } catch (error) {
          console.error('Error downloading profile picture for new user:', error);
        }
      }
      
      const newUser = new User({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails && profile.emails[0] ? profile.emails[0].value : '',
        profilePicture: {
          path: profilePicturePath,
          contentType: 'image/png'
        }
      });
      
      await newUser.save();
      return done(null, newUser);
    }
  } catch (error) {
    console.error('Error in Google Strategy:', error);
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    console.log('Google auth callback successful:', req.user);
    res.redirect('/');
  }
);

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

app.get('/api/user', (req, res) => {
  if (req.isAuthenticated() && req.user) {
    const { _id, name, email, profilePicture, description, createdAt } = req.user;
    return res.json({
      id: _id,
      name,
      email,
      photo: profilePicture.path || '/default-profile.png',
      description: description || '',
      createdAt: createdAt
    });
  } else {
    return res.status(401).json({ error: 'Not authenticated' });
  }
});

// Get public user profile
app.get('/api/users/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('name profilePicture description createdAt');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user._id,
      name: user.name,
      photo: user.profilePicture.path || '/default-profile.png',
      description: user.description || '',
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    if (error.kind === 'ObjectId') {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// New endpoint for Reporting Posts
app.post('/api/posts/:postId/report', isAuthenticated, async (req, res) => {
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

    // Optional: Check if user has already reported this post for the same reason to prevent duplicates
    // const existingReport = post.reports.find(report => 
    //   report.reporter.equals(reporterId) && report.reasonType === reasonType
    // );
    // if (existingReport) {
    //   return res.status(409).json({ error: 'You have already reported this post for this reason.' });
    // }

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

// New endpoint for Poll Voting
app.post('/api/posts/:postId/vote', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const { optionIndex } = req.body; // Client will send the index of the chosen option
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

    // Check if user has already voted. For simplicity, we'll add a 'voters' array to each option.
    // This requires a schema change if we want to strictly enforce one vote per user per poll.
    // For now, let's assume the schema is: pollOptions: [{ option: String, votes: Number, voters: [ObjectId] }]
    // If 'voters' field is not in schema, this part will need adjustment or a different strategy.
    // Current schema: pollOptions: [{ option: String, votes: Number }] - so we can't check individual voters easily without schema change.
    //
    // Alternative: Add a top-level 'votedBy' array to the Post schema for polls:
    // votedBy: [{ userId: ObjectId, optionIndex: Number }]
    // This would be more robust for preventing multiple votes by the same user on a poll.
    //
    // For this iteration, sticking to the current schema, we'll just increment votes.
    // A more advanced implementation would prevent multiple votes.

    const existingVoteIndex = post.usersWhoVoted.findIndex(vote => vote.userId.equals(userId));

    if (existingVoteIndex > -1) {
      // User has voted before, check if it's for a different option
      const previousVote = post.usersWhoVoted[existingVoteIndex];
      if (previousVote.optionIndex === optionIndex) {
        // Voted for the same option again, no change needed or return specific message
        return res.json({
          message: 'You have already voted for this option.',
          pollOptions: post.pollOptions.map(opt => ({ option: opt.option, votes: opt.votes })),
          usersWhoVoted: post.usersWhoVoted
        });
      }

      // Decrement vote from the old option
      if (post.pollOptions[previousVote.optionIndex]) {
        post.pollOptions[previousVote.optionIndex].votes = Math.max(0, post.pollOptions[previousVote.optionIndex].votes - 1);
      }
      
      // Update to the new option index
      post.usersWhoVoted[existingVoteIndex].optionIndex = optionIndex;
      post.pollOptions[optionIndex].votes += 1;

    } else {
      // New vote
      post.pollOptions[optionIndex].votes += 1;
      post.usersWhoVoted.push({ userId, optionIndex });
    }
    
    await post.save();

    // Return the updated poll options (or the whole post)
    // Also indicate if the current user has voted and which option.
    res.json({
      pollOptions: post.pollOptions.map(opt => ({ 
        option: opt.option, 
        votes: opt.votes 
      })),
      usersWhoVoted: post.usersWhoVoted // Send this back so client can update UI
    });

  } catch (error) {
    console.error('Error voting in poll:', error);
    res.status(500).json({ error: 'Failed to cast vote.' });
  }
});

// Delete a comment or reply (hard delete)
app.delete('/api/comments/:commentId', isAuthenticated, async (req, res) => {
  try {
    const { commentId } = req.params;
    const userId = req.user._id;

    const comment = await Comment.findById(commentId);

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found.' });
    }

    // Check if the current user is the author of the comment
    if (comment.author.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'User not authorized to delete this comment.' });
    }

    if (comment.parentComment === null) {
      // This is a top-level comment, delete it and all its children recursively
      await deleteCommentAndChildren(commentId);
    } else {
      // This is a reply, just delete the reply itself
      // Its direct children's parentComment field will now point to a non-existent ID.
      // The buildCommentTree logic will need to handle this to show "[reply deleted]".
      await Comment.findByIdAndDelete(commentId);
    }

    res.json({ success: true, message: 'Comment deleted successfully.' });

  } catch (error) {
    console.error('Error deleting comment:', error);
    if (error.kind === 'ObjectId') {
        return res.status(400).json({ error: 'Invalid Comment ID format.' });
    }
    res.status(500).json({ error: 'Failed to delete comment.' });
  }
});

// Update user description
app.put('/api/user/description', isAuthenticated, async (req, res) => {
  try {
    const { description } = req.body;
    if (typeof description !== 'string') {
      return res.status(400).json({ error: 'Invalid description format' });
    }
    if (description.length > 500) { // Max length from schema
        return res.status(400).json({ error: 'Description is too long. Maximum 500 characters.' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.description = description;
    await user.save();
    
    // Update the user object in the session
    req.user.description = user.description;

    res.json({ success: true, description: user.description });
  } catch (error) {
    console.error('Error updating user description:', error);
    res.status(500).json({ error: 'Failed to update description' });
  }
});

// Update user name
app.put('/api/user/name', isAuthenticated, async (req, res) => {
  try {
    const { name } = req.body;
    if (typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Invalid name format' });
    }
    if (name.length > 50) { // Max length from schema
        return res.status(400).json({ error: 'Name is too long. Maximum 50 characters.' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.name = name;
    await user.save();
    
    // Update the user object in the session
    req.user.name = user.name;

    res.json({ success: true, name: user.name });
  } catch (error) {
    console.error('Error updating user name:', error);
    res.status(500).json({ error: 'Failed to update name' });
  }
});

// Upload profile picture endpoint
app.post('/api/user/profile-picture', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Delete old profile picture if it exists and is stored locally
    if (user.profilePicture.path && user.profilePicture.path.startsWith('/uploads/')) {
      const oldFilePath = path.join(__dirname, user.profilePicture.path);
      if (fs.existsSync(oldFilePath)) {
        try {
          fs.unlinkSync(oldFilePath);
          console.log('Deleted old profile picture:', oldFilePath);
        } catch (error) {
          console.error('Error deleting old profile picture:', error);
        }
      }
    }

    // Update user with new profile picture
    user.profilePicture = {
      path: `/uploads/profile_pics/${req.file.filename}`,
      contentType: req.file.mimetype
    };
    
    await user.save();
    
    // Update the user object in the session
    req.user.profilePicture = user.profilePicture;

    console.log('Profile picture updated successfully:', user.profilePicture.path);

    res.json({
      success: true,
      photo: user.profilePicture.path
    });
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error('Error cleaning up uploaded file:', unlinkError);
      }
    }
    
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});

// Get posts with populated author data
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', 'name profilePicture')
      .sort({ createdAt: -1 });

    const currentUserId = req.user ? req.user._id : null;

    const postsWithDetails = await Promise.all(
      posts.map(async (post) => {
        // Fetch all comments for the post
        const allCommentsRaw = await Comment.find({ post: post._id })
          .populate('author', '_id name profilePicture')
          .sort({ createdAt: 1 });

        // Function to recursively build comment tree
        const buildCommentTree = (parentId) => {
          return allCommentsRaw
            .filter(comment => String(comment.parentComment) === String(parentId)) // Compare as strings
            .map(comment => {
              let replyingTo = null;
              if (comment.parentComment) {
                const parentCommentObject = allCommentsRaw.find(c => String(c._id) === String(comment.parentComment));
                if (parentCommentObject) {
                  // Parent comment exists
                  replyingTo = {
                    id: parentCommentObject.author._id,
                    name: parentCommentObject.author.name
                  };
                } else {
                  // Parent comment was likely deleted (it's a reply to a deleted reply)
                  replyingTo = {
                    id: null,
                    name: "Reply deleted" // Changed placeholder text
                  };
                }
              }
              return {
                id: comment._id,
                content: comment.content,
                author: {
                  id: comment.author._id,
                  name: comment.author.name,
                  photo: comment.author.profilePicture.path || '/default-profile.png'
                },
                likes: comment.likes.length,
                isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                createdAt: comment.createdAt.toISOString(),
                parentComment: comment.parentComment,
                replyingTo: replyingTo, // Updated logic here
                replies: buildCommentTree(comment._id)
              };
            });
        };
        
        // Get top-level comments (those without a parentComment or parentComment is null)
        const topLevelComments = allCommentsRaw
            .filter(comment => !comment.parentComment) // Filter for actual top-level comments
            .map(comment => ({
                id: comment._id,
                content: comment.content,
                author: {
                    id: comment.author._id,
                    name: comment.author.name,
                    photo: comment.author.profilePicture.path || '/default-profile.png'
                },
                likes: comment.likes.length,
                isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                createdAt: comment.createdAt.toISOString(),
                parentComment: null, // Explicitly null for top-level
                replyingTo: null,    // Top-level comments are not replying to anyone
                replies: buildCommentTree(comment._id)
            }));


        return {
          id: post._id,
          title: post.title,
          content: post.content,
          postType: post.postType, // Include postType
          pollOptions: post.pollOptions ? post.pollOptions.map(opt => ({ // Include pollOptions
            option: opt.option,
            votes: opt.votes,
            // _id: opt._id // Optionally include option ID if needed by frontend for voting, though index is used now
          })) : [],
          author: {
            id: post.author._id,
            name: post.author.name,
            photo: post.author.profilePicture.path || '/default-profile.png'
          },
          likes: post.likes.length,
          isLiked: currentUserId ? post.likes.includes(currentUserId) : false,
          createdAt: post.createdAt.toISOString(),
          comments: topLevelComments,
          usersWhoVoted: post.postType === 'poll' ? post.usersWhoVoted : undefined // Include if it's a poll
        };
      })
    );

    res.json(postsWithDetails);
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Create new post
app.post('/api/posts', isAuthenticated, async (req, res) => {
  try {
    const { title, content, postType, pollOptions } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    const newPostData = {
      title,
      content,
      author: req.user._id,
      postType: postType || 'normal' // Default to 'normal' if not provided
    };

    if (postType === 'poll') {
      if (!pollOptions || !Array.isArray(pollOptions) || pollOptions.length < 2) {
        return res.status(400).json({ error: 'Polls require at least two options.' });
      }
      // Sanitize poll options
      newPostData.pollOptions = pollOptions.map(opt => ({
        option: String(opt.option).trim(), // Ensure option is a string and trim whitespace
        votes: 0 // Votes start at 0
      })).filter(opt => opt.option); // Filter out any empty options

      if (newPostData.pollOptions.length < 2) {
        return res.status(400).json({ error: 'Polls require at least two valid options.' });
      }
    }

    const post = new Post(newPostData);
    await post.save();
    await post.populate('author', 'name profilePicture');

    const responsePost = {
      id: post._id,
      title: post.title,
      content: post.content,
      postType: post.postType,
      pollOptions: post.pollOptions, // Ensure pollOptions are returned
      author: {
        id: post.author._id,
        name: post.author.name,
        photo: post.author.profilePicture.path || '/default-profile.png'
      },
      likes: [], // Initialize likes
      isLiked: false, // Initialize isLiked
      createdAt: post.createdAt.toISOString(),
      comments: []
    };

    res.status(201).json(responsePost); // Use 201 for resource creation
  } catch (error) {
    console.error('Error creating post:', error);
    if (error.name === 'ValidationError') {
        return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Add comment to post
app.post('/api/posts/:postId/comments', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comment = new Comment({
      content,
      author: req.user._id,
      post: postId
    });

    await comment.save();
    await comment.populate('author', 'name profilePicture');

    const responseComment = {
      id: comment._id,
      content: comment.content,
      author: {
        id: comment.author._id,
        name: comment.author.name,
        photo: comment.author.profilePicture.path || '/default-profile.png'
      },
      createdAt: comment.createdAt.toISOString()
    };

    res.json(responseComment);
  } catch (error) {
    console.error('Error creating comment:', error);
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

// Reply to a comment
app.post('/api/comments/:commentId/replies', isAuthenticated, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required for a reply.' });
    }

    const parentComment = await Comment.findById(commentId);
    if (!parentComment) {
      return res.status(404).json({ error: 'Parent comment not found.' });
    }

    const reply = new Comment({
      content,
      author: req.user._id,
      post: parentComment.post, // Associate reply with the same post
      parentComment: commentId
    });

    await reply.save();
    await reply.populate('author', 'name profilePicture');

    const responseReply = {
      id: reply._id,
      content: reply.content,
      author: {
        id: reply.author._id,
        name: reply.author.name,
        photo: reply.author.profilePicture.path || '/default-profile.png'
      },
      post: reply.post,
      parentComment: reply.parentComment,
      likes: [],
      createdAt: reply.createdAt.toISOString()
    };

    res.status(201).json(responseReply);
  } catch (error) {
    console.error('Error creating reply:', error);
    res.status(500).json({ error: 'Failed to create reply.' });
  }
});

// Like/Unlike a post
app.post('/api/posts/:postId/like', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.user._id;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    const likedIndex = post.likes.indexOf(userId);
    if (likedIndex > -1) {
      // User has liked, so unlike
      post.likes.splice(likedIndex, 1);
    } else {
      // User has not liked, so like
      post.likes.push(userId);
    }

    await post.save();
    
    // We don't need to return the full post object with populated author and comments here.
    // Just the like status and count.
    res.json({ 
      likesCount: post.likes.length,
      isLiked: post.likes.includes(userId) 
    });

  } catch (error) {
    console.error('Error liking/unliking post:', error);
    res.status(500).json({ error: 'Failed to update post like status.' });
  }
});

// Like/Unlike a comment
app.post('/api/comments/:commentId/like', isAuthenticated, async (req, res) => {
  try {
    const { commentId } = req.params;
    const userId = req.user._id;

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found.' });
    }

    const likedIndex = comment.likes.indexOf(userId);
    if (likedIndex > -1) {
      comment.likes.splice(likedIndex, 1);
    } else {
      comment.likes.push(userId);
    }

    await comment.save();
    
    res.json({
      likesCount: comment.likes.length,
      isLiked: comment.likes.includes(userId)
    });

  } catch (error) {
    console.error('Error liking/unliking comment:', error);
    res.status(500).json({ error: 'Failed to update comment like status.' });
  }
});

// Delete a post and its associated comments/replies
app.delete('/api/posts/:postId', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.user._id;

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    // Check if the current user is the author of the post
    if (post.author.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'User not authorized to delete this post.' });
    }

    // Delete all comments and replies associated with the post
    // Mongoose doesn't have automatic cascading delete for this scenario with `parentComment` self-references.
    // We first delete all comments (which includes replies as they are also comments) linked to the post.
    await Comment.deleteMany({ post: postId });

    // Then delete the post itself
    await Post.findByIdAndDelete(postId);

    res.json({ success: true, message: 'Post and associated comments deleted successfully.' });

  } catch (error) {
    console.error('Error deleting post:', error);
    if (error.kind === 'ObjectId') {
        return res.status(400).json({ error: 'Invalid Post ID format.' });
    }
    res.status(500).json({ error: 'Failed to delete post.' });
  }
});


// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  // Handle multer errors
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ error: 'File upload error: ' + error.message });
  }
  
  // Handle other errors
  if (error.message === 'Not an image! Please upload only images.') {
    return res.status(400).json({ error: 'Please upload only image files.' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});