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

const { User, Post, Comment, Notification } = require('./schema');

const app = express();
const PORT = process.env.PORT || 8082;

const development = process.env.NODE_ENV !== 'production';

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
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Not an image! Please upload only images.'), false);
    }
  },
});

// Multer configuration for post attachments
const postAttachmentUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images and videos are allowed.'), false);
    }
  },
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

// Middleware
app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use((req, res, next) => {
  if (!development) {
    // Multiple ways to detect HTTPS in production
    const isHttps = 
      req.headers['x-forwarded-proto'] === 'https' ||
      req.headers['x-forwarded-ssl'] === 'on' ||
      req.headers['x-arr-ssl'] || // Azure
      req.connection.encrypted ||
      req.secure ||
      (req.headers.host && req.headers.host.includes('https')) ||
      (req.get('referer') && req.get('referer').startsWith('https://'));
    
    if (isHttps) {
      req.secure = true;
      req.protocol = 'https';
      console.log('=== HTTPS DETECTED ===');
      console.log('HTTPS detection method:', 
        req.headers['x-forwarded-proto'] === 'https' ? 'x-forwarded-proto' :
        req.headers['x-forwarded-ssl'] === 'on' ? 'x-forwarded-ssl' :
        req.headers['x-arr-ssl'] ? 'x-arr-ssl' :
        req.connection.encrypted ? 'connection.encrypted' :
        req.secure ? 'req.secure' :
        req.headers.host?.includes('https') ? 'host header' :
        'referer header'
      );
      console.log('===================');
    } else {
      console.log('=== HTTPS NOT DETECTED ===');
      console.log('x-forwarded-proto:', req.headers['x-forwarded-proto']);
      console.log('x-forwarded-ssl:', req.headers['x-forwarded-ssl']);
      console.log('connection.encrypted:', req.connection.encrypted);
      console.log('req.secure:', req.secure);
      console.log('host:', req.headers.host);
      console.log('referer:', req.get('referer'));
      console.log('========================');
    }
  }
  next();
});

// Updated session configuration that's more flexible
const sessionConfig = {
  name: 'peerspace.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/PeerSpace',
    touchAfter: 24 * 3600,
    ttl: 24 * 60 * 60
  }),
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
};

if (!development) {
  // In production, we'll dynamically set secure based on the request
  sessionConfig.cookie.secure = false; // We'll handle this per-request
  sessionConfig.cookie.sameSite = 'lax';
} else {
  sessionConfig.cookie.secure = false;
  sessionConfig.cookie.sameSite = 'lax';
}

app.use(session(sessionConfig));

// Add middleware to dynamically set secure cookies for HTTPS requests
app.use((req, res, next) => {
  if (!development && req.secure && req.session) {
    // For HTTPS requests, ensure the session cookie will be secure
    req.session.cookie.secure = true;
  }
  next();
});
// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Helper function to download and save profile picture from Google
async function downloadProfilePicture(url, filename) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', async () => {
        const buffer = Buffer.concat(chunks);
        const ext = path.extname(url).split('?')[0] || '.png';
        const key = `profile_pics/${filename}${ext}`;
        const params = {
          Bucket: BUCKET_NAME,
          Key: key,
          Body: buffer,
          ContentType: response.headers['content-type'],
          ACL: 'public-read',
        };
        try {
          const result = await s3.upload(params).promise();
          resolve(result.Location);
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

// Function to generate a unique username
async function generateUniqueUsername(email) {
    let username = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_.]/g, '');
    if (username.length < 3) {
        username = `user_${username}${uuidv4().substring(0, 8)}`;
    }
    username = username.substring(0, 20);

    let user = await User.findOne({ username });
    while (user) {
        const randomSuffix = uuidv4().substring(0, 4);
        username = `${username.substring(0, 15)}_${randomSuffix}`;
        user = await User.findOne({ username });
    }
    return username;
}

const CALLBACK_URL = development
  ? 'http://localhost:8082/auth/google/callback'
  : 'https://peerspace.ipo-servers.net/auth/google/callback';

console.log('Google OAuth Callback URL:', CALLBACK_URL); // Debug log

// FIXED Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  console.log('Google Strategy called with profile:', profile.id, profile.displayName); // Debug log
  try {
    let user = await User.findOne({ googleId: profile.id });

    const profilePictureUrl = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
    
    if (user) {
      console.log('Existing user found:', user.username); // Debug log
      // Update last login and displayName
      user.lastLogin = new Date();
      user.displayName = profile.displayName;
      
      const hasCustomProfilePic = user.profilePicture.path && !user.profilePicture.path.includes('googleusercontent.com');
      
      if (!hasCustomProfilePic && profilePictureUrl) {
        try {
          const filename = `google_${uuidv4()}`;
          const s3Url = await downloadProfilePicture(profilePictureUrl, filename);
          
          user.profilePicture = {
            path: s3Url,
            contentType: 'image/png'
          };
        } catch (error) {
          console.error('Error downloading profile picture:', error);
          // Keep existing profile picture on error
        }
      }
      
      await user.save();
      console.log('User updated and saved'); // Debug log
      return done(null, user);
    } else {
      console.log('Creating new user'); // Debug log
      // New user - download Google profile picture
      let profilePicturePath = null;
      
      if (profilePictureUrl) {
        try {
          const filename = `google_${uuidv4()}`;
          profilePicturePath = await downloadProfilePicture(profilePictureUrl, filename);
        } catch (error) {
          console.error('Error downloading profile picture for new user:', error);
        }
      }

      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
      const username = await generateUniqueUsername(email);
      
      const newUser = new User({
        googleId: profile.id,
        username: username,
        displayName: profile.displayName,
        email: email,
        profilePicture: {
          path: profilePicturePath,
          contentType: 'image/png'
        }
      });
      
      await newUser.save();
      console.log('New user created:', newUser.username); // Debug log
      return done(null, newUser);
    }
  } catch (error) {
    console.error('Error in Google Strategy:', error);
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  console.log('>>> SERIALIZE USER CALLED WITH:', user._id); // Debug log
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  console.log('>>> DESERIALIZE USER CALLED WITH ID:', id);
  try {
    const user = await User.findById(id);
    console.log('>>> USER FOUND:', user ? user.username : 'null');
    done(null, user);
  } catch (err) {
    console.error('>>> DESERIALIZE ERROR:', err);
    done(err, null);
  }
});

// ENHANCED Authentication middleware with better logging
const isAuthenticated = (req, res, next) => {
  console.log('=== AUTH CHECK ===');
  console.log('Session ID:', req.sessionID);
  console.log('Session data:', req.session);
  console.log('User authenticated?', req.isAuthenticated());
  console.log('User object:', req.user ? { id: req.user._id, username: req.user.username } : 'null');
  console.log('Cookies:', req.headers.cookie);
  console.log('==================');
  
  if (req.isAuthenticated() && req.user) {
    console.log('✓ User is authenticated:', req.user.username);
    return next();
  }
  console.log('✗ User is NOT authenticated');
  res.status(401).json({ error: 'Not authenticated' });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/inbox', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'inbox.html'));
});

// API Routes
app.get('/api/notifications', isAuthenticated, async (req, res) => {
  try {
    const notifications = await Notification.find({ user: req.user._id })
      .populate('sender', 'displayName')
      .populate('post')
      .sort({ createdAt: -1 });

    console.log('Fetched notifications:', JSON.stringify(notifications, null, 2));

    const responseNotifications = notifications
      .filter(n => n.post) // Filter out notifications where the post has been deleted
      .map(n => ({
        _id: n._id,
        message: `<strong>${n.sender.displayName}</strong> mentioned you in <strong>${n.post.title}</strong>.`,
        link: `/#/post/${n.post._id}#comment-${n.comment}`,
        read: n.read,
        createdAt: n.createdAt
    }));
    res.json(responseNotifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.get('/api/notifications/unread-count', isAuthenticated, async (req, res) => {
    try {
        const count = await Notification.countDocuments({ user: req.user._id, read: false });
        res.json({ count });
    } catch (error) {
        console.error('Error fetching unread notification count:', error);
        res.status(500).json({ error: 'Failed to fetch unread notification count' });
    }
});

app.post('/api/notifications/:notificationId/read', isAuthenticated, async (req, res) => {
    try {
        const { notificationId } = req.params;
        const notification = await Notification.findOneAndUpdate(
            { _id: notificationId, user: req.user._id },
            { read: true },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        res.status(500).json({ error: 'Failed to mark notification as read' });
    }
});

// FIXED Google Auth routes with better error handling
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/?error=auth_failed',
    failureMessage: true 
  }),
  (req, res) => {
    console.log('=== GOOGLE CALLBACK SUCCESS ===');
    console.log('User authenticated:', req.user ? req.user.username : 'null');
    console.log('Session before save:', req.session);
    console.log('Session ID:', req.sessionID);
    
    // Force session save before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Error saving session:', err);
        return res.redirect('/?error=session_save_failed');
      }
      console.log('Session saved successfully');
      console.log('Redirecting to home...');
      res.redirect('/');
    });
  }
);

app.post('/auth/logout', (req, res) => {
  console.log('Logout requested for user:', req.user ? req.user.username : 'anonymous');
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
        return res.status(500).json({ error: 'Session destroy failed' });
      }
      res.clearCookie('peerspace.sid'); // Explicitly expire the cookie
      res.json({ success: true });
    });
  });
});

// ENHANCED user endpoint with better logging
app.get('/api/user', (req, res) => {
  console.log('=== /api/user REQUEST ===');
  console.log('Headers:', {
    'user-agent': req.headers['user-agent'],
    'cookie': req.headers.cookie,
    'referer': req.headers.referer
  });
  console.log('Session ID:', req.sessionID);
  console.log('Session:', req.session);
  console.log('Is authenticated?', req.isAuthenticated());
  console.log('User object:', req.user);
  
  if (req.isAuthenticated() && req.user) {
    console.log('✓ Sending user data for:', req.user.username);
    const { _id, username, displayName, email, profilePicture, description, createdAt, theme } = req.user;
    return res.json({
      id: _id,
      username,
      displayName,
      email,
      photo: profilePicture.path || '/default-profile.png',
      description: description || '',
      createdAt: createdAt,
      theme: theme
    });
  } else {
    console.log('✗ User not authenticated - sending 401');
    return res.status(401).json({ error: 'Not authenticated' });
  }
});

// User search for @-mentions
app.get('/api/users/search', isAuthenticated, async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.json([]);
    }
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { displayName: { $regex: query, $options: 'i' } }
      ]
    }).select('username displayName').limit(10);
    res.json(users);
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Get public user profile
app.get('/api/users/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('username displayName profilePicture description createdAt');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user._id,
      username: user.username,
      displayName: user.displayName,
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

app.get('/api/users/by-username/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username displayName profilePicture description createdAt');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user._id,
            username: user.username,
            displayName: user.displayName,
            photo: user.profilePicture.path || '/default-profile.png',
            description: user.description || '',
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Error fetching user by username:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// Rest of your API routes remain the same...
// (Including all the post, comment, notification, user update endpoints)
// I'll keep the rest as they are since the main issue was with session/auth configuration

// [All your other API endpoints continue here unchanged...]

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
        return res.json({
          message: 'You have already voted for this option.',
          pollOptions: post.pollOptions.map(opt => ({ option: opt.option, votes: opt.votes })),
          usersWhoVoted: post.usersWhoVoted
        });
      }

      if (post.pollOptions[previousVote.optionIndex]) {
        post.pollOptions[previousVote.optionIndex].votes = Math.max(0, post.pollOptions[previousVote.optionIndex].votes - 1);
      }
      
      post.usersWhoVoted[existingVoteIndex].optionIndex = optionIndex;
      post.pollOptions[optionIndex].votes += 1;

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

// Delete a comment or reply (hard delete)
app.delete('/api/comments/:commentId', isAuthenticated, async (req, res) => {
  try {
    const { commentId } = req.params;
    const userId = req.user._id;

    const comment = await Comment.findById(commentId);

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found.' });
    }

    if (comment.author.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'User not authorized to delete this comment.' });
    }

    if (comment.parentComment === null) {
      await deleteCommentAndChildren(commentId);
    } else {
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
    if (description.length > 500) {
        return res.status(400).json({ error: 'Description is too long. Maximum 500 characters.' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.description = description;
    await user.save();
    
    req.user.description = user.description;

    res.json({ success: true, description: user.description });
  } catch (error) {
    console.error('Error updating user description:', error);
    res.status(500).json({ error: 'Failed to update description' });
  }
});

// Update user display name
app.put('/api/user/displayName', isAuthenticated, async (req, res) => {
  try {
    const { displayName } = req.body;
    if (typeof displayName !== 'string' || displayName.trim().length === 0) {
      return res.status(400).json({ error: 'Invalid display name format' });
    }
    if (displayName.length > 50) {
        return res.status(400).json({ error: 'Display name is too long. Maximum 50 characters.' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.displayName = displayName;
    await user.save();
    
    req.user.displayName = user.displayName;

    res.json({ success: true, displayName: user.displayName });
  } catch (error) {
    console.error('Error updating user display name:', error);
    res.status(500).json({ error: 'Failed to update display name' });
  }
});

// Update username
app.put('/api/user/username', isAuthenticated, async (req, res) => {
    try {
        const { username } = req.body;
        if (typeof username !== 'string' || !/^[a-zA-Z0-9_.]+$/.test(username) || username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Invalid username format or length.' });
        }

        const existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser && existingUser._id.toString() !== req.user._id.toString()) {
            return res.status(409).json({ error: 'Username is already taken.' });
        }

        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        user.username = username.toLowerCase();
        await user.save();

        req.user.username = user.username;

        res.json({ success: true, username: user.username });
    } catch (error) {
        console.error('Error updating username:', error);
        res.status(500).json({ error: 'Failed to update username.' });
    }
});

// Upload profile picture endpoint
app.put('/api/user/theme', isAuthenticated, async (req, res) => {
  try {
    const { theme } = req.body;
    if (!theme || !['light', 'dark', 'midnight'].includes(theme)) {
      return res.status(400).json({ error: 'Invalid theme' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.theme = theme;
    await user.save();

    req.user.theme = user.theme;

    res.json({ success: true, theme: user.theme });
  } catch (error) {
    console.error('Error updating user theme:', error);
    res.status(500).json({ error: 'Failed to update theme' });
  }
});

app.post('/api/user/profile-picture', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const ext = req.file.originalname.split('.').pop();
    const key = `profile_pics/${uuidv4()}.${ext}`;

    const params = {
      Bucket: BUCKET_NAME,
      Key: key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype,
      ACL: 'public-read',
    };

    const result = await s3.upload(params).promise();

    user.profilePicture = {
      path: result.Location,
      contentType: req.file.mimetype,
    };

    await user.save();

    req.user.profilePicture = user.profilePicture;

    console.log('Profile picture updated successfully:', user.profilePicture.path);

    res.json({
      success: true,
      photo: user.profilePicture.path,
    });
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});


// Get posts with populated author data
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', 'username displayName profilePicture')
      .sort({ createdAt: -1 });

    const currentUserId = req.user ? req.user._id : null;

    const postsWithDetails = await Promise.all(
      posts.map(async (post) => {
        // Fetch all comments for the post
        const allCommentsRaw = await Comment.find({ post: post._id })
          .populate('author', '_id username displayName profilePicture')
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
                    username: parentCommentObject.author.username
                  };
                } else {
                  // Parent comment was likely deleted (it's a reply to a deleted reply)
                  replyingTo = {
                    id: null,
                    username: "Reply deleted" // Changed placeholder text
                  };
                }
              }
              return {
                id: comment._id,
                content: comment.content,
                author: {
                  id: comment.author._id,
                  username: comment.author.username,
                  displayName: comment.author.displayName,
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
                    username: comment.author.username,
                    displayName: comment.author.displayName,
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
          attachments: post.attachments,
          pollOptions: post.pollOptions ? post.pollOptions.map(opt => ({ // Include pollOptions
            option: opt.option,
            votes: opt.votes,
            // _id: opt._id // Optionally include option ID if needed by frontend for voting, though index is used now
          })) : [],
          author: {
            id: post.author._id,
            username: post.author.username,
            displayName: post.author.displayName,
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
app.post('/api/posts', isAuthenticated, postAttachmentUpload.array('attachments', 15), async (req, res) => {
  try {
    const { title, content, postType } = req.body;
    let { pollOptions } = req.body;

    if (pollOptions) {
      pollOptions = JSON.parse(pollOptions);
    }

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    if (title.length > 75) {
      return res.status(400).json({ error: 'Title cannot exceed 75 characters.' });
    }

    if (content.length > 2500) {
      return res.status(400).json({ error: 'Content cannot exceed 2500 characters.' });
    }

    const newPostData = {
      title,
      content,
      author: req.user._id,
      postType: postType || 'normal', // Default to 'normal' if not provided
      attachments: []
    };

    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const key = `post_attachments/${uuidv4()}-${file.originalname}`;
        const params = {
          Bucket: BUCKET_NAME,
          Key: key,
          Body: file.buffer,
          ContentType: file.mimetype,
          ACL: 'public-read',
        };
        const result = await s3.upload(params).promise();
        newPostData.attachments.push({
          url: result.Location,
          fileType: file.mimetype.startsWith('image/') ? 'image' : 'video'
        });
      }
    }

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

      for (const opt of newPostData.pollOptions) {
        if (opt.option.length > 75) {
          return res.status(400).json({ error: 'Poll option cannot exceed 75 characters.' });
        }
      }
    }

    const post = new Post(newPostData);
    await post.save();
    await post.populate('author', 'username displayName profilePicture');
    await createNotificationsForMentions(content, post._id, null, req.user._id);

    const responsePost = {
      id: post._id,
      title: post.title,
      content: post.content,
      postType: post.postType,
      attachments: post.attachments,
      pollOptions: post.pollOptions, // Ensure pollOptions are returned
      author: {
        id: post.author._id,
        username: post.author.username,
        displayName: post.author.displayName,
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

    if (content.length > 1000) {
      return res.status(400).json({ error: 'Comment cannot exceed 1000 characters.' });
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
    await comment.populate('author', 'username displayName profilePicture');
    await createNotificationsForMentions(content, postId, comment._id, req.user._id);

    const responseComment = {
      id: comment._id,
      content: comment.content,
      author: {
        id: comment.author._id,
        username: comment.author.username,
        displayName: comment.author.displayName,
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

    if (content.length > 1000) {
      return res.status(400).json({ error: 'Reply cannot exceed 1000 characters.' });
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
    await reply.populate('author', 'username displayName profilePicture');
    await createNotificationsForMentions(content, parentComment.post, reply._id, req.user._id);

    const responseReply = {
      id: reply._id,
      content: reply.content,
      author: {
        id: reply.author._id,
        username: reply.author.username,
        displayName: reply.author.displayName,
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

// Helper function to parse mentions and create notifications
async function createNotificationsForMentions(text, postId, commentId, senderId) {
    const mentionRegex = /@(\w+)/g;
    const mentions = text.match(mentionRegex);

    if (mentions) {
        const mentionedUsernames = [...new Set(mentions.map(mention => mention.substring(1).toLowerCase()))];

        for (const username of mentionedUsernames) {
            const user = await User.findOne({ username: username });
            if (user && user._id.toString() !== senderId.toString()) {
                const notification = new Notification({
                    user: user._id,
                    sender: senderId,
                    type: 'mention',
                    post: postId,
                    comment: commentId,
                });
                await notification.save();
            }
        }
    }
}

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

// Get a single post
app.get('/api/posts/:postId', async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId)
            .populate('author', 'username displayName profilePicture');

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        
        const comments = await Comment.find({ post: req.params.postId })
            .populate('author', 'username displayName profilePicture')
            .sort({ createdAt: 'asc' });

        const postWithComments = post.toObject();
        postWithComments.comments = comments;

        res.json(postWithComments);
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ error: 'Failed to fetch post' });
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
  if (development) {
    console.log(`Development server running on http://localhost:${PORT}`);
  } else {
    console.log(`HTTPS Server running on https://peerspace.ipo-servers.net:${PORT}`);
  }
});
