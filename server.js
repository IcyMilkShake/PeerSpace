const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { v4: uuidv4 } = require('uuid');
const { Server } = require("socket.io");
const AWS = require('aws-sdk');
const ffmpeg = require('fluent-ffmpeg');
const axios = require('axios');
const cheerio = require('cheerio');
require('dotenv').config();

const { User, Post, Comment, Notification, FriendRequest, VoiceChannel } = require('./schema');

const app = express();

// Create temporary directories for video processing
const uploadsDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
if (!fs.existsSync(processedDir)) {
  fs.mkdirSync(processedDir);
}
const PORT = process.env.PORT || 8082;

const development = process.env.NODE_ENV !== 'production';

AWS.config.update({
  region: 'ap-southeast-7',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const s3 = new AWS.S3();
const BUCKET_NAME = 'peerspace-database';
const channelTimeouts = {};

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
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
      cb(null, `${uuidv4()}-${file.originalname}`);
    },
  }),
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

// Recursively deletes a comment and all its replies.
async function deleteCommentAndChildren(commentId) {
  const comment = await Comment.findById(commentId);
  if (!comment) return;

  if (comment.voiceChannel) {
    await VoiceChannel.findByIdAndDelete(comment.voiceChannel);
  }

  // Find and delete all replies to this comment first.
  const children = await Comment.find({ parentComment: commentId });
  for (const child of children) {
    await deleteCommentAndChildren(child._id);
  }
  // After all children are deleted, delete the comment itself.
  await Comment.findByIdAndDelete(commentId);
}

// Middleware
app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// This middleware detects if the server is running behind a proxy and using HTTPS.
app.use((req, res, next) => {
  if (!development) {
    const isHttps =
      req.headers['x-forwarded-proto'] === 'https' ||
      req.headers['x-forwarded-ssl'] === 'on' ||
      req.headers['x-arr-ssl'] ||
      req.connection.encrypted ||
      req.secure ||
      (req.headers.host && req.headers.host.includes('https')) ||
      (req.get('referer') && req.get('referer').startsWith('https://'));
    if (isHttps) {
      req.secure = true;
      req.protocol = 'https';
    }
  }
  next();
});

// Configures the session settings for the application.
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
  sessionConfig.cookie.secure = false;
  sessionConfig.cookie.sameSite = 'lax';
} else {
  sessionConfig.cookie.secure = false;
  sessionConfig.cookie.sameSite = 'lax';
}

app.use(session(sessionConfig));

// Sets the session cookie to be secure if the request is over HTTPS.
app.use((req, res, next) => {
  if (!development && req.secure && req.session) {
    req.session.cookie.secure = true;
  }
  next();
});

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Downloads a user's profile picture from Google and saves it to S3.
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

// Generates a unique username for a new user based on their email.
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

// Sets up the Google OAuth 2.0 strategy for Passport.
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    const profilePictureUrl = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
    
    if (user) {
      user.lastLogin = new Date();
      if (!user.displayName) {
        user.displayName = profile.displayName;
      }
      const hasCustomProfilePic = user.profilePicture.path && !user.profilePicture.path.includes('googleusercontent.com');
      
      if (!hasCustomProfilePic && profilePictureUrl) {
        try {
          const filename = `google_${uuidv4()}`;
          const s3Url = await downloadProfilePicture(profilePictureUrl, filename);
          user.profilePicture = { path: s3Url, contentType: 'image/png' };
        } catch (error) {
          console.error('Error downloading profile picture:', error);
        }
      }
      await user.save();
      return done(null, user);
    } else {
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
        profilePicture: { path: profilePicturePath, contentType: 'image/png' }
      });
      
      await newUser.save();
      return done(null, newUser);
    }
  } catch (error) {
    console.error('Error in Google Strategy:', error);
    return done(error, null);
  }
}));

// Saves user's ID to the session.
passport.serializeUser((user, done) => {
  done(null, user._id);
});

// Retrieves user's data from the database using the ID from the session.
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    console.error('>>> DESERIALIZE ERROR:', err);
    done(err, null);
  }
});

// Checks if a user is logged in.
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated() && req.user) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
};

// Routes
// Serves the main page of the application.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serves the user profile page.
app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});

// Serves the user's inbox page.
app.get('/inbox', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'inbox.html'));
});

// API Routes
// Gets all notifications for the logged-in user.
app.get('/api/notifications', isAuthenticated, async (req, res) => {
  try {
    const notifications = await Notification.find({ user: req.user._id })
      .populate('sender', 'displayName')
      .populate('post')
      .sort({ createdAt: -1 });

    const responseNotifications = notifications
      .filter(n => n.post)
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

// Gets the number of unread notifications and pending friend requests.
app.get('/api/notification-counts', isAuthenticated, async (req, res) => {
    try {
        const unreadNotifications = await Notification.countDocuments({ user: req.user._id, read: false });
        const pendingFriendRequests = await FriendRequest.countDocuments({ recipient: req.user._id, status: 'pending' });

        res.json({
            unreadNotifications,
            pendingFriendRequests
        });
    } catch (error) {
        console.error('Error fetching notification counts:', error);
        res.status(500).json({ error: 'Failed to fetch notification counts' });
    }
});

// Gets the number of unread notifications for the logged-in user.
app.get('/api/notifications/unread-count', isAuthenticated, async (req, res) => {
    try {
        const count = await Notification.countDocuments({ user: req.user._id, read: false });
        res.json({ count });
    } catch (error) {
        console.error('Error fetching unread notification count:', error);
        res.status(500).json({ error: 'Failed to fetch unread notification count' });
    }
});

// Marks a specific notification as read.
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

// Starts the Google authentication process.
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' })
);

// Handles the callback from Google after authentication.
app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/?error=auth_failed',
    failureMessage: true 
  }),
  (req, res) => {
    req.session.save((err) => {
      if (err) {
        console.error('Error saving session:', err);
        return res.redirect('/?error=session_save_failed');
      }
      res.redirect('/');
    });
  }
);

// Logs out the current user.
app.post('/auth/logout', (req, res) => {
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
      res.clearCookie('peerspace.sid');
      res.json({ success: true });
    });
  });
});

// Gets the data for the currently logged-in user.
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated() && req.user) {
    const { _id, username, displayName, email, profilePicture, bannerPicture, description, createdAt, theme, audioSettings } = req.user;
    return res.json({
      id: _id,
      username,
      displayName,
      email,
      photo: profilePicture.path || '/default-profile.png',
      banner: bannerPicture.path || '/default-banner.png',
      description: description || '',
      createdAt: createdAt,
      theme: theme,
      audioSettings: audioSettings
    });
  } else {
    return res.status(401).json({ error: 'Not authenticated' });
  }
});

// Searches for users to mention in a post or comment.
app.get('/api/users/search', async (req, res) => {
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
    }).select('_id username displayName profilePicture').limit(10);
    
    const results = users.map(user => ({
        _id: user._id,
        username: user.username,
        displayName: user.displayName,
        photo: user.profilePicture ? user.profilePicture.path : null
    }));

    res.json(results);
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Gets the public profile information for a user.
app.get('/api/users/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('username displayName profilePicture bannerPicture description createdAt');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user._id,
      username: user.username,
      displayName: user.displayName,
      photo: user.profilePicture.path || '/default-profile.png',
      banner: user.bannerPicture.path || null,
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

// Gets a user's profile by their username.
app.get('/api/users/by-username/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username displayName profilePicture bannerPicture description createdAt');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user._id,
            username: user.username,
            displayName: user.displayName,
            photo: user.profilePicture.path || '/default-profile.png',
            banner: user.bannerPicture.path || null,
            description: user.description || '',
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Error fetching user by username:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// Gets content for a specific user, with filtering and sorting.
app.get('/api/users/:userId/content', async (req, res) => {
    try {
        const { userId } = req.params;
        const { contentType, sortBy } = req.query;
        const currentUserId = req.user ? req.user._id : null;
        const authorId = new mongoose.Types.ObjectId(userId);

        if (contentType === 'posts') {
            let sortedPosts;

            if (sortBy === 'likes') {
                const postIds = await Post.aggregate([
                    { $match: { author: authorId } },
                    { $addFields: { likesCount: { $size: "$likes" } } },
                    { $sort: { likesCount: -1, createdAt: -1 } },
                    { $project: { _id: 1 } }
                ]);
                const ids = postIds.map(p => p._id);
                const unsortedPosts = await Post.find({ _id: { $in: ids } }).populate('author', 'username displayName profilePicture').populate('voiceChannel');
                sortedPosts = ids.map(id => unsortedPosts.find(p => p._id.equals(id)));
            } else if (sortBy === 'comments') {
                const postIds = await Post.aggregate([
                    { $match: { author: authorId } },
                    { $lookup: { from: 'comments', localField: '_id', foreignField: 'post', as: 'comments' } },
                    { $addFields: { commentCount: { $size: "$comments" } } },
                    { $sort: { commentCount: -1, createdAt: -1 } },
                    { $project: { _id: 1 } }
                ]);
                const ids = postIds.map(p => p._id);
                const unsortedPosts = await Post.find({ _id: { $in: ids } }).populate('author', 'username displayName profilePicture').populate('voiceChannel');
                sortedPosts = ids.map(id => unsortedPosts.find(p => p._id.equals(id)));
            } else {
                const sortOption = (sortBy === 'oldest') ? { createdAt: 1 } : { createdAt: -1 };
                sortedPosts = await Post.find({ author: authorId })
                    .populate('author', 'username displayName profilePicture')
                    .populate('voiceChannel')
                    .sort(sortOption);
            }
            
            const postsWithDetails = await Promise.all(
              sortedPosts.map(async (post) => {
                const allCommentsRaw = await Comment.find({ post: post._id })
                  .populate('author', '_id username displayName profilePicture')
                  .sort({ createdAt: 1 });

                const buildCommentTree = (parentId) => {
                  return allCommentsRaw
                    .filter(comment => String(comment.parentComment) === String(parentId))
                    .map(comment => {
                      let replyingTo = null;
                      if (comment.parentComment) {
                        const parentCommentObject = allCommentsRaw.find(c => String(c._id) === String(comment.parentComment));
                        if (parentCommentObject) {
                          replyingTo = { id: parentCommentObject.author._id, username: parentCommentObject.author.username };
                        } else {
                          replyingTo = { id: null, username: "Reply deleted" };
                        }
                      }
                      return {
                        id: comment._id, content: comment.content,
                        author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
                        likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                        createdAt: comment.createdAt.toISOString(), parentComment: comment.parentComment,
                        replyingTo: replyingTo, linkPreview: comment.linkPreview,
                  voiceChannel: comment.voiceChannel,
                        replies: buildCommentTree(comment._id)
                      };
                    });
                };
                
                const topLevelComments = allCommentsRaw
                    .filter(comment => !comment.parentComment)
                    .map(comment => ({
                        id: comment._id, content: comment.content,
                        author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
                        likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                        createdAt: comment.createdAt.toISOString(), parentComment: null, replyingTo: null,
                        linkPreview: comment.linkPreview,
                  voiceChannel: comment.voiceChannel,
                        replies: buildCommentTree(comment._id)
                    }));

                return {
                  id: post._id, title: post.title, content: post.content,
                  linkPreview: post.linkPreview, postType: post.postType,
                  attachments: post.attachments,
                  pollOptions: post.pollOptions ? post.pollOptions.map(opt => ({ option: opt.option, votes: opt.votes })) : [],
                  voiceChannel: post.voiceChannel,
                  author: { id: post.author._id, username: post.author.username, displayName: post.author.displayName, photo: post.author.profilePicture.path || '/default-profile.png' },
                  likes: post.likes.length, isLiked: currentUserId ? post.likes.includes(currentUserId) : false,
                  createdAt: post.createdAt.toISOString(),
                  comments: topLevelComments,
                  usersWhoVoted: post.postType === 'poll' ? post.usersWhoVoted : undefined
                };
              })
            );
            return res.json(postsWithDetails);

        } else if (contentType === 'comments') {
            const sortOption = (sortBy === 'oldest') ? { createdAt: 1 } : { createdAt: -1 };
            const comments = await Comment.find({ author: authorId })
                .populate('author', 'username displayName profilePicture')
                .populate({ path: 'post', select: 'title' })
                .sort(sortOption);
            
            const commentsWithExistingPosts = comments.filter(comment => comment.post);
            
            return res.json(commentsWithExistingPosts);
        } else {
            return res.status(400).json({ error: 'Invalid content type' });
        }

    } catch (error) {
        console.error('Error fetching user content:', error);
        res.status(500).json({ error: 'Failed to fetch user content' });
    }
});


// Reports a post for inappropriate content.
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

// Allows a user to vote in a poll.
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

// Deletes a comment or a reply.
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

// Updates a user's description.
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

// Updates a user's display name.
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

// Updates a user's username.
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

// Updates the theme for the logged-in user.
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

// Uploads a new profile picture for the user.
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

    res.json({
      success: true,
      photo: user.profilePicture.path,
    });
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    res.status(500).json({ error: 'Failed to upload profile picture' });
  }
});

// FRIEND REQUESTS

// Send a friend request
app.post('/api/friend-request', isAuthenticated, async (req, res) => {
    const { recipientId } = req.body;
    const requesterId = req.user._id;

    if (requesterId.equals(recipientId)) {
        return res.status(400).json({ error: "You cannot send a friend request to yourself." });
    }

    try {
        const existingRequest = await FriendRequest.findOne({
            $or: [
                { requester: requesterId, recipient: recipientId },
                { requester: recipientId, recipient: requesterId }
            ]
        });

        if (existingRequest) {
            return res.status(400).json({ error: "A friend request already exists between you and this user." });
        }
        
        const recipient = await User.findById(recipientId);
        if (!recipient) {
            return res.status(404).json({ error: 'Recipient not found' });
        }

        const areFriends = recipient.friends.includes(requesterId);
        if (areFriends) {
            return res.status(400).json({ error: 'You are already friends with this user.' });
        }

        const newRequest = new FriendRequest({
            requester: requesterId,
            recipient: recipientId
        });

        await newRequest.save();
        res.status(201).json({ success: true, message: 'Friend request sent.' });

    } catch (error) {
        console.error('Error sending friend request:', error);
        res.status(500).json({ error: 'Failed to send friend request.' });
    }
});

// Get pending friend requests
app.get('/api/friend-requests', isAuthenticated, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ recipient: req.user._id, status: 'pending' })
            .populate('requester', 'username displayName profilePicture');
        res.json(requests);
    } catch (error) {
        console.error('Error fetching friend requests:', error);
        res.status(500).json({ error: 'Failed to fetch friend requests.' });
    }
});

// Get sent friend requests that are pending
app.get('/api/friend-requests/sent', isAuthenticated, async (req, res) => {
    try {
        const requests = await FriendRequest.find({ requester: req.user._id, status: 'pending' })
            .populate('recipient', 'username displayName profilePicture');
        res.json(requests);
    } catch (error) {
        console.error('Error fetching sent friend requests:', error);
        res.status(500).json({ error: 'Failed to fetch sent friend requests.' });
    }
});

// Accept a friend request
app.put('/api/friend-requests/:requestId/accept', isAuthenticated, async (req, res) => {
    try {
        const { requestId } = req.params;
        const recipientId = req.user._id;

        const request = await FriendRequest.findById(requestId);

        if (!request || !request.recipient.equals(recipientId) || request.status !== 'pending') {
            return res.status(404).json({ error: 'Friend request not found or you are not authorized to accept it.' });
        }

        const requesterId = request.requester;

        await User.findByIdAndUpdate(requesterId, { $addToSet: { friends: recipientId } });
        await User.findByIdAndUpdate(recipientId, { $addToSet: { friends: requesterId } });

        await FriendRequest.findByIdAndDelete(requestId);

        res.json({ success: true, message: 'Friend request accepted.' });

    } catch (error) {
        console.error('Error accepting friend request:', error);
        res.status(500).json({ error: 'Failed to accept friend request.' });
    }
});

// Decline a friend request
app.put('/api/friend-requests/:requestId/decline', isAuthenticated, async (req, res) => {
    try {
        const { requestId } = req.params;
        const userId = req.user._id;

        const request = await FriendRequest.findById(requestId);

        if (!request || (!request.recipient.equals(userId) && !request.requester.equals(userId)) || request.status !== 'pending') {
            return res.status(404).json({ error: 'Friend request not found or you are not authorized to decline it.' });
        }

        await FriendRequest.findByIdAndDelete(requestId);

        res.json({ success: true, message: 'Friend request declined.' });

    } catch (error) {
        console.error('Error declining friend request:', error);
        res.status(500).json({ error: 'Failed to decline friend request.' });
    }
});

// Get friends list
app.get('/api/friends', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate('friends', 'username displayName profilePicture');
        res.json(user.friends);
    } catch (error) {
        console.error('Error fetching friends list:', error);
        res.status(500).json({ error: 'Failed to fetch friends list.' });
    }
});

// Unfriend a user
app.delete('/api/friends/:friendId', isAuthenticated, async (req, res) => {
    try {
        const { friendId } = req.params;
        const currentUserId = req.user._id;

        // Remove friend from current user's list
        await User.findByIdAndUpdate(currentUserId, { $pull: { friends: friendId } });

        // Remove current user from friend's list
        await User.findByIdAndUpdate(friendId, { $pull: { friends: currentUserId } });

        res.json({ success: true, message: 'Friend removed.' });

    } catch (error) {
        console.error('Error removing friend:', error);
        res.status(500).json({ error: 'Failed to remove friend.' });
    }
});

// Cancel a friend request
app.delete('/api/friend-request/:recipientId', isAuthenticated, async (req, res) => {
    try {
        const { recipientId } = req.params;
        const requesterId = req.user._id;

        const result = await FriendRequest.findOneAndDelete({
            requester: requesterId,
            recipient: recipientId,
            status: 'pending'
        });

        if (!result) {
            return res.status(404).json({ error: 'Friend request not found or already handled.' });
        }

        res.json({ success: true, message: 'Friend request cancelled.' });

    } catch (error) {
        console.error('Error cancelling friend request:', error);
        res.status(500).json({ error: 'Failed to cancel friend request.' });
    }
});

// Get friend status
app.get('/api/friend-status/:userId', isAuthenticated, async (req, res) => {
    try {
        const { userId } = req.params;
        const currentUserId = req.user._id;

        if (currentUserId.equals(userId)) {
            return res.json({ status: 'self' });
        }

        const areFriends = req.user.friends.includes(userId);
        if (areFriends) {
            return res.json({ status: 'friends' });
        }

        const pendingRequest = await FriendRequest.findOne({
            $or: [
                { requester: currentUserId, recipient: userId },
                { requester: userId, recipient: currentUserId }
            ],
            status: 'pending'
        });

        if (pendingRequest) {
            if (pendingRequest.requester.equals(currentUserId)) {
                return res.json({ status: 'sent' });
            } else {
                return res.json({ status: 'received' });
            }
        }

        res.json({ status: 'none' });

    } catch (error) {
        console.error('Error fetching friend status:', error);
        res.status(500).json({ error: 'Failed to fetch friend status.' });
    }
});

// Updates the audio settings for the logged-in user.
app.put('/api/user/audio-settings', isAuthenticated, async (req, res) => {
  try {
    const { inputDevice, outputDevice, micVolume } = req.body;
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.audioSettings = { inputDevice, outputDevice, micVolume };
    await user.save();
    res.json({ success: true, audioSettings: user.audioSettings });
  } catch (error) {
    console.error('Error updating audio settings:', error);
    res.status(500).json({ error: 'Failed to update audio settings' });
  }
});

// Uploads a new banner picture for the user.
app.post('/api/user/banner-picture', isAuthenticated, upload.single('bannerPicture'), async (req, res) => {
  try {
    console.log('Banner upload request received');
    if (!req.file) {
      console.log('No file uploaded');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log('Finding user...');
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log('User not found');
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User found:', user.username);

    const ext = req.file.originalname.split('.').pop();
    const key = `banner_pics/${uuidv4()}.${ext}`;

    const params = {
      Bucket: BUCKET_NAME,
      Key: key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype,
      ACL: 'public-read',
    };

    console.log('Uploading to S3...');
    const result = await s3.upload(params).promise();
    console.log('S3 upload successful:', result.Location);

    user.bannerPicture = {
      path: result.Location,
      contentType: req.file.mimetype,
    };

    console.log('Saving user...');
    await user.save();
    console.log('User saved successfully');

    req.user.bannerPicture = user.bannerPicture;

    res.json({
      success: true,
      photo: user.bannerPicture.path,
    });
  } catch (error) {
    console.error('Error uploading banner picture:', error);
    res.status(500).json({ error: 'Failed to upload banner picture' });
  }
});


// Helper function to populate post details
async function populatePostDetails(post, currentUserId) {
    const allCommentsRaw = await Comment.find({ post: post._id })
        .populate('author', '_id username displayName profilePicture')
        .sort({ createdAt: 1 });

    const buildCommentTree = (parentId) => {
        return allCommentsRaw
            .filter(comment => String(comment.parentComment) === String(parentId))
            .map(comment => {
                let replyingTo = null;
                if (comment.parentComment) {
                    const parentCommentObject = allCommentsRaw.find(c => String(c._id) === String(comment.parentComment));
                    if (parentCommentObject) {
                        replyingTo = { id: parentCommentObject.author._id, username: parentCommentObject.author.username };
                    } else {
                        replyingTo = { id: null, username: "Reply deleted" };
                    }
                }
                return {
                    id: comment._id, content: comment.content,
                    author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
                    likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
                    createdAt: comment.createdAt.toISOString(), parentComment: comment.parentComment,
                    replyingTo: replyingTo, linkPreview: comment.linkPreview,
                    voiceChannel: comment.voiceChannel,
                    replies: buildCommentTree(comment._id)
                };
            });
    };
    
    const topLevelComments = allCommentsRaw
        .filter(comment => !comment.parentComment)
        .map(comment => ({
            id: comment._id, content: comment.content,
            author: { id: comment.author._id, username: comment.author.username, displayName: comment.author.displayName, photo: comment.author.profilePicture.path || '/default-profile.png' },
            likes: comment.likes.length, isLiked: currentUserId ? comment.likes.includes(currentUserId) : false,
            createdAt: comment.createdAt.toISOString(), parentComment: null, replyingTo: null,
            linkPreview: comment.linkPreview,
            voiceChannel: comment.voiceChannel,
            replies: buildCommentTree(comment._id)
        }));

    return {
        id: post._id, title: post.title, content: post.content,
        linkPreview: post.linkPreview, postType: post.postType,
        attachments: post.attachments,
        pollOptions: post.pollOptions ? post.pollOptions.map(opt => ({ option: opt.option, votes: opt.votes })) : [],
        voiceChannel: post.voiceChannel,
        author: { id: post.author._id, username: post.author.username, displayName: post.author.displayName, photo: post.author.profilePicture.path || '/default-profile.png' },
        likes: post.likes.length, isLiked: currentUserId ? post.likes.includes(currentUserId) : false,
        createdAt: post.createdAt.toISOString(),
        comments: topLevelComments,
        usersWhoVoted: post.postType === 'poll' ? post.usersWhoVoted : undefined
    };
}

app.get('/api/posts/friends-recent', isAuthenticated, async (req, res) => {
    try {
        const currentUserId = req.user._id;
        const friends = req.user.friends;

        if (!friends || friends.length === 0) {
            return res.json([]);
        }

        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

        const recentFriendPosts = await Post.find({
            author: { $in: friends },
            createdAt: { $gte: threeDaysAgo }
        }).populate('author', 'username displayName profilePicture');

        for (let i = recentFriendPosts.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [recentFriendPosts[i], recentFriendPosts[j]] = [recentFriendPosts[j], recentFriendPosts[i]];
        }
        
        const postsWithDetails = await Promise.all(
            recentFriendPosts.map(post => populatePostDetails(post, currentUserId))
        );

        res.json(postsWithDetails);

    } catch (error) {
        console.error('Error fetching recent friend posts:', error);
        res.status(500).json({ error: 'Failed to fetch recent friend posts' });
    }
});

// Gets all posts and their details.
app.get('/api/posts', async (req, res) => {
  try {
    const currentUserId = req.user ? req.user._id : null;
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = req.query.filter || 'all';
    let query = {};
    if (filter !== 'all') {
      if (filter === 'normal') {
        query.$or = [{ postType: 'normal' }, { postType: { $exists: false } }];
      } else {
        query.postType = filter;
      }
    }

    const excludeIdsStr = req.query.exclude_ids || '';
    if (excludeIdsStr) {
        const excludedIds = excludeIdsStr.split(',').filter(id => mongoose.Types.ObjectId.isValid(id));
        if (excludedIds.length > 0) {
            query._id = { $nin: excludedIds };
        }
    }

    const totalPosts = await Post.countDocuments(query);
    
    const posts = await Post.find(query)
      .populate('author', 'username displayName profilePicture')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const postsWithDetails = await Promise.all(
        posts.map(post => populatePostDetails(post, currentUserId))
    );
    
    res.json({
        posts: postsWithDetails,
        hasMore: (skip + posts.length) < totalPosts
    });

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Creates a new post.
app.post('/api/posts', isAuthenticated, postAttachmentUpload.array('attachments', 15), async (req, res) => {
  try {
    const { title, content, postType } = req.body;
    let { pollOptions } = req.body;

    if (pollOptions) {
      pollOptions = JSON.parse(pollOptions);
    }

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
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
      postType: postType || 'normal',
      attachments: []
    };

    const linkPreview = await generateLinkPreview(content);
    if (linkPreview) {
        newPostData.linkPreview = linkPreview;
    }


    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        if (file.mimetype.startsWith('video/')) {
          const outputPath = path.join(processedDir, `${Date.now()}-output.mp4`);
          await new Promise((resolve, reject) => {
            ffmpeg(file.path)
              .outputOptions([
                '-vf', 'scale=min(1280\\,iw):-2,format=yuv420p',
                '-c:v', 'libx264',
                '-preset', 'veryfast',
                '-crf', '23',
                '-movflags', '+faststart',
                '-c:a', 'aac'
              ])
              .on('end', () => {
                resolve(outputPath);
              })
              .on('error', (err, stdout, stderr) => {
                console.error('❌ FFmpeg error:', err.message);
                console.error('FFmpeg stdout:', stdout);
                console.error('FFmpeg stderr:', stderr);
                reject(err);
              })
              .save(outputPath);
          });

          const fileContent = fs.readFileSync(outputPath);
          const key = `post_attachments/${uuidv4()}-output.mp4`;
          const params = {
            Bucket: BUCKET_NAME,
            Key: key,
            Body: fileContent,
            ContentType: 'video/mp4',
            ACL: 'public-read',
          };
          const result = await s3.upload(params).promise();
          newPostData.attachments.push({
            url: result.Location,
            fileType: 'video'
          });

          fs.unlinkSync(file.path);
          fs.unlinkSync(outputPath);
        } else if (file.mimetype.startsWith('image/')) {
          const fileContent = fs.readFileSync(file.path);
          const key = `post_attachments/${uuidv4()}-${file.originalname}`;
          const params = {
            Bucket: BUCKET_NAME,
            Key: key,
            Body: fileContent,
            ContentType: file.mimetype,
            ACL: 'public-read',
          };
          const result = await s3.upload(params).promise();
          newPostData.attachments.push({
            url: result.Location,
            fileType: 'image'
          });
          fs.unlinkSync(file.path);
        }
      }
    }

    if (postType === 'poll') {
      if (!pollOptions || !Array.isArray(pollOptions) || pollOptions.length < 2) {
        return res.status(400).json({ error: 'Polls require at least two options.' });
      }
      newPostData.pollOptions = pollOptions.map(opt => ({
        option: String(opt.option).trim(),
        votes: 0
      })).filter(opt => opt.option);

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

    if (post.voiceChannel) {
      await VoiceChannel.findByIdAndUpdate(post.voiceChannel, { post: post._id });
    }

    await post.populate('author', 'username displayName profilePicture');
    await createNotificationsForMentions(content, post._id, null, req.user._id);

    const responsePost = {
      id: post._id,
      title: post.title,
      content: post.content,
      postType: post.postType,
      attachments: post.attachments,
      pollOptions: post.pollOptions,
      linkPreview: post.linkPreview,
      voiceChannel: post.voiceChannel,
      author: {
        id: post.author._id,
        username: post.author.username,
        displayName: post.author.displayName,
        photo: post.author.profilePicture.path || '/default-profile.png'
      },
      likes: [],
      isLiked: false,
      createdAt: post.createdAt.toISOString(),
      comments: []
    };

    res.status(201).json(responsePost);
  } catch (error) {
    console.error('Error creating post:', error);
    if (error.name === 'ValidationError') {
        return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Adds a comment to a post.
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

    const linkPreview = await generateLinkPreview(content);
    if (linkPreview) {
      comment.linkPreview = linkPreview;
    }

    await comment.save();

    if (comment.voiceChannel) {
      await VoiceChannel.findByIdAndUpdate(comment.voiceChannel, { comment: comment._id });
    }

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
      likes: 0,
      isLiked: false,
      createdAt: comment.createdAt.toISOString(),
      parentComment: null,
      replyingTo: null,
      linkPreview: comment.linkPreview,
      voiceChannel: comment.voiceChannel,
      replies: []
    };

    res.json(responseComment);
  } catch (error) {
    console.error('Error creating comment:', error);
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

// Adds a reply to a comment.
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

    const parentComment = await Comment.findById(commentId).populate('author', 'id username');
    if (!parentComment) {
      return res.status(404).json({ error: 'Parent comment not found.' });
    }

    const reply = new Comment({
      content,
      author: req.user._id,
      post: parentComment.post,
      parentComment: commentId
    });

    const linkPreview = await generateLinkPreview(content);
    if (linkPreview) {
      reply.linkPreview = linkPreview;
    }

    await reply.save();

    if (reply.voiceChannel) {
      await VoiceChannel.findByIdAndUpdate(reply.voiceChannel, { comment: reply._id });
    }

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
      likes: 0,
      isLiked: false,
      createdAt: reply.createdAt.toISOString(),
      parentComment: reply.parentComment,
      replyingTo: {
        id: parentComment.author._id,
        username: parentComment.author.username
      },
      linkPreview: reply.linkPreview,
      voiceChannel: reply.voiceChannel,
      replies: []
    };

    res.status(201).json(responseReply);
  } catch (error) {
    console.error('Error creating reply:', error);
    res.status(500).json({ error: 'Failed to create reply.' });
  }
});

// Generates a preview for the first link found in a piece of text.
async function generateLinkPreview(content) {
  const urlRegex = /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])|(\bwww\.[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
  const urls = content.match(urlRegex);

  if (urls && urls.length > 0) {
    try {
      let url = urls[0];
      if (!url.match(/^[a-zA-Z]+:\/\//)) {
        url = 'http://' + url;
      }

      const { data } = await axios.get(url, { timeout: 5000 });
      const $ = cheerio.load(data);

      const getMetaTag = (name) => {
        return (
          $(`meta[property="og:${name}"]`).attr('content') ||
          $(`meta[name="twitter:${name}"]`).attr('content') ||
          $(`meta[name="${name}"]`).attr('content')
        );
      };

      const title = getMetaTag('title') || $('title').first().text();
      const description = getMetaTag('description') || $('p').first().text();
      let image = getMetaTag('image');

      if (image && image.trim() && !image.startsWith('http')) {
        try {
            const urlObject = new URL(url);
            image = new URL(image, urlObject.origin).href;
        } catch (e) {
            console.error(`Invalid image URL found for ${url}: ${image}`);
            image = null;
        }
      }

      if (title || description) {
          return {
            url: url,
            title: title ? title.trim() : '',
            description: description ? description.trim().substring(0, 200) : '',
            image: image,
          };
      }
    } catch (previewError) {
    }
  }
  return null;
}

// Creates notifications for any users mentioned in a post or comment.
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

// Likes or unlikes a post.
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
      post.likes.splice(likedIndex, 1);
    } else {
      post.likes.push(userId);
    }

    await post.save();
    
    res.json({ 
      likesCount: post.likes.length,
      isLiked: post.likes.includes(userId) 
    });

  } catch (error) {
    console.error('Error liking/unliking post:', error);
    res.status(500).json({ error: 'Failed to update post like status.' });
  }
});

// Creates a voice channel for a post.
app.post('/api/posts/:postId/voice-channel', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const { name } = req.body;
    const userId = req.user._id;

    // Check if user already has an active voice channel
    const existingChannel = await VoiceChannel.findOne({ creator: userId });
    if (existingChannel) {
      return res.status(409).json({
        error: 'You have already created a voice channel.',
        channelId: existingChannel._id,
        postId: existingChannel.post,
        commentId: existingChannel.comment
      });
    }

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }
    if (post.author.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'You are not authorized to create a voice channel on this post.' });
    }
    if (post.voiceChannel) {
      return res.status(409).json({ error: 'This post already has a voice channel.' });
    }

    const voiceChannel = new VoiceChannel({
      post: postId,
      name: name || 'Voice Channel',
      creator: userId,
      participants: []
    });
    await voiceChannel.save();

    post.voiceChannel = voiceChannel._id;
    await post.save();

    io.emit('voice-channel-created', {
        itemType: 'post',
        itemId: postId,
        voiceChannel: voiceChannel
    });

    res.status(201).json({ success: true, voiceChannelId: voiceChannel._id });

  } catch (error) {
    console.error('Error creating voice channel for post:', error);
    res.status(500).json({ error: 'Failed to create voice channel.' });
  }
});

// Likes or unlikes a comment.
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

// Creates a voice channel for a comment.
app.post('/api/comments/:commentId/voice-channel', isAuthenticated, async (req, res) => {
    try {
        const { commentId } = req.params;
        const { name } = req.body;
        const userId = req.user._id;

        // Check if user already has an active voice channel
        const existingChannel = await VoiceChannel.findOne({ creator: userId });
        if (existingChannel) {
            return res.status(409).json({
                error: 'You have already created a voice channel.',
                channelId: existingChannel._id,
                postId: existingChannel.post,
                commentId: existingChannel.comment
            });
        }

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found.' });
        }
        if (comment.author.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to create a voice channel on this comment.' });
        }
        if (comment.voiceChannel) {
            return res.status(409).json({ error: 'This comment already has a voice channel.' });
        }

        const voiceChannel = new VoiceChannel({
            post: comment.post,
            comment: commentId,
            name: name || 'Voice Channel',
            creator: userId,
            participants: []
        });
        await voiceChannel.save();

        comment.voiceChannel = voiceChannel._id;
        await comment.save();

        io.emit('voice-channel-created', {
            itemType: 'comment',
            itemId: commentId,
            voiceChannel: voiceChannel
        });

        res.status(201).json({ success: true, voiceChannelId: voiceChannel._id });

    } catch (error) {
        console.error('Error creating voice channel for comment:', error);
        res.status(500).json({ error: 'Failed to create voice channel.' });
    }
});

// Searches for posts.
app.get('/api/posts/search', async (req, res) => {
  try {
    const { q } = req.query;

    if (!q) {
      return res.json([]);
    }

    const posts = await Post.find({
      $or: [
        { title: { $regex: q, $options: 'i' } },
        { content: { $regex: q, $options: 'i' } }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .select('title content');

    const results = posts.map(post => ({
      id: post._id,
      title: post.title,
      content: post.content.substring(0, 100) + (post.content.length > 100 ? '...' : '')
    }));
    
    res.json(results);

  } catch (error) {
    console.error('Error searching posts:', error);
    res.status(500).json({ error: 'Failed to search posts' });
  }
});

// Gets a single post by its ID.
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
        postWithComments.comments = comments.map(c => c.toObject());

        res.json(postWithComments);
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ error: 'Failed to fetch post' });
    }
});

// Deletes a voice channel.
app.delete('/api/voice-channel/:channelId', isAuthenticated, async (req, res) => {
  try {
    const { channelId } = req.params;
    const userId = req.user._id;

    const voiceChannel = await VoiceChannel.findById(channelId);

    if (!voiceChannel) {
      return res.status(404).json({ error: 'Voice channel not found.' });
    }

    if (voiceChannel.creator.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'You are not authorized to delete this voice channel.' });
    }

    await VoiceChannel.findByIdAndDelete(channelId);

    if (voiceChannel.post) {
        await Post.findByIdAndUpdate(voiceChannel.post, { $unset: { voiceChannel: "" } });
        io.emit('voice-channel-deleted', { channelId: channelId, postId: voiceChannel.post });
    } else if (voiceChannel.comment) {
        await Comment.findByIdAndUpdate(voiceChannel.comment, { $unset: { voiceChannel: "" } });
        io.emit('voice-channel-deleted', { channelId: channelId, commentId: voiceChannel.comment });
    }
    
    console.log(`User ${userId} deleted voice channel ${channelId}`);
    res.json({ success: true, message: 'Voice channel deleted successfully.' });

  } catch (error) {
    console.error('Error deleting voice channel:', error);
    res.status(500).json({ error: 'Failed to delete voice channel.' });
  }
});

// Gets the current participants of a voice channel.
app.get('/api/voice-channel/:channelId', async (req, res) => {
  try {
    const { channelId } = req.params;
    const socketsInRoom = await io.in(channelId).fetchSockets();
    const usersInRoom = socketsInRoom.map(s => ({ userId: s.userId, socketId: s.id }));
      
    const userIds = usersInRoom.map(u => u.userId).filter(Boolean);
    if (userIds.length === 0) {
      return res.json([]);
    }

    const userObjects = await User.find({ '_id': { $in: userIds } }).select('username displayName profilePicture');

    const participants = userObjects.map(user => {
        const socketInfo = usersInRoom.find(u => u.userId === user._id.toString());
        return { ...user.toObject(), socketId: socketInfo ? socketInfo.socketId : null };
    }).filter(p => p.socketId);

    res.json(participants);
  } catch (error) {
    console.error('Error fetching voice channel participants:', error);
    res.status(500).json({ error: 'Failed to fetch participants' });
  }
});

// Deletes a post and all its comments.
app.delete('/api/posts/:postId', isAuthenticated, async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.user._id;

    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    if (post.author.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'User not authorized to delete this post.' });
    }

    if (post.voiceChannel) {
      await VoiceChannel.findByIdAndDelete(post.voiceChannel);
    }

    const comments = await Comment.find({ post: postId });
    for (const comment of comments) {
      await deleteCommentAndChildren(comment._id);
    }

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


// Catches and handles any errors that occur in the application.
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ error: 'File upload error: ' + error.message });
  }
  
  if (error.message === 'Not an image! Please upload only images.') {
    return res.status(400).json({ error: 'Please upload only image files.' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});


// Starts the server.
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: development ? "http://localhost:8082" : "https://peerspace.ipo-servers.net",
    methods: ["GET", "POST"]
  }
});

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  const leaveChannel = async (channelId, userId) => {
    try {
      if (!channelId || !userId) return;
      console.log(`User ${userId} (${socket.id}) leaving channel ${channelId}`);
      socket.leave(channelId);

      const updatedChannel = await VoiceChannel.findByIdAndUpdate(
        channelId,
        { $pull: { participants: userId } },
        { new: true }
      );

      if (updatedChannel && updatedChannel.participants.length === 0) {
        console.log(`Channel ${channelId} is now empty. Starting deletion timer.`);
        const timeoutId = setTimeout(async () => {
          try {
            const finalCheckChannel = await VoiceChannel.findById(channelId);
            if (finalCheckChannel && finalCheckChannel.participants.length === 0) {
                console.log(`Timer expired for ${channelId}. Deleting channel.`);
                await VoiceChannel.findByIdAndDelete(channelId);
                
                if (finalCheckChannel.post) {
                    await Post.findByIdAndUpdate(finalCheckChannel.post, { $unset: { voiceChannel: "" } });
                    io.emit('voice-channel-deleted', { channelId: channelId, postId: finalCheckChannel.post });
                } else if (finalCheckChannel.comment) {
                    await Comment.findByIdAndUpdate(finalCheckChannel.comment, { $unset: { voiceChannel: "" } });
                    io.emit('voice-channel-deleted', { channelId: channelId, commentId: finalCheckChannel.comment });
                }
                console.log(`Deleted empty voice channel ${channelId}`);
            } else {
                console.log(`Timer expired for ${channelId}, but it is no longer empty. Deletion cancelled.`);
            }
          } catch (error) {
            console.error(`Error during voice channel auto-deletion for ${channelId}:`, error);
          } finally {
            delete channelTimeouts[channelId.toString()];
          }
        }, 60000);

        channelTimeouts[channelId.toString()] = timeoutId;
      } else if (updatedChannel) {
        console.log(`User left channel ${channelId}. ${updatedChannel.participants.length} participants remaining.`);
      }

      socket.to(channelId).emit('user-left', { socketId: socket.id });

      // Use the same logic as join-channel to get the updated participant list
      const socketsInRoom = await io.in(channelId).fetchSockets();
      const usersInRoom = socketsInRoom.map(s => ({ userId: s.userId, socketId: s.id }));
      const userIds = usersInRoom.map(u => u.userId).filter(Boolean);
      const userObjects = await User.find({ '_id': { $in: userIds } }).select('username displayName profilePicture');
      const participants = userObjects.map(user => {
          const socketInfo = usersInRoom.find(u => u.userId === user._id.toString());
          return { ...user.toObject(), socketId: socketInfo ? socketInfo.socketId : null };
      }).filter(p => p.socketId);

      io.in(channelId).emit('update-participants', participants);
      io.emit('voice-channel-updated', { channelId, participants });
    } catch (error) {
      console.error('Error in leaveChannel:', error);
    }
  };

  socket.on('join-channel', async ({ channelId, userId }) => {
    try {
      if (channelTimeouts[channelId]) {
        clearTimeout(channelTimeouts[channelId]);
        delete channelTimeouts[channelId];
        console.log(`[JOIN] Cleared auto-delete timeout for channel ${channelId}`);
      }
      const channel = await VoiceChannel.findById(channelId);
      if (!channel) {
        // Or emit an error event to the client
        return console.error(`Attempted to join non-existent channel: ${channelId}`);
      }
      
      // Check if the user is already in the participants list to allow re-joining
      const isAlreadyParticipant = channel.participants.some(pId => pId.equals(userId));

      if (channel.participants.length >= 10 && !isAlreadyParticipant) {
        socket.emit('channel-full');
        return;
      }

      console.log(`User ${userId} (${socket.id}) joining channel ${channelId}`);
      socket.join(channelId);
      socket.userId = userId;
      socket.channelId = channelId;

      await VoiceChannel.findByIdAndUpdate(channelId, { $addToSet: { participants: userId } });

      const socketsInRoom = await io.in(channelId).fetchSockets();
      const usersInRoom = socketsInRoom.map(s => ({ userId: s.userId, socketId: s.id }));
      
      const userIds = usersInRoom.map(u => u.userId).filter(Boolean);
      const userObjects = await User.find({ '_id': { $in: userIds } }).select('username displayName profilePicture');

      const participants = userObjects.map(user => {
          const socketInfo = usersInRoom.find(u => u.userId === user._id.toString());
          return { ...user.toObject(), socketId: socketInfo ? socketInfo.socketId : null };
      }).filter(p => p.socketId);
      
      // Send other participants to the new user
      socket.emit('existing-participants', { participants: participants.filter(p => p.socketId !== socket.id) });
      
      // Let existing participants know about the new user
      const newUser = participants.find(p => p.socketId === socket.id);
      if (newUser) {
          socket.to(channelId).emit('user-joined', { user: newUser });
      }
      
      // Broadcast updated participant list to everyone
      io.in(channelId).emit('update-participants', participants);
      io.emit('voice-channel-updated', { channelId, participants });

    } catch (error) {
      console.error('Error in join-channel:', error);
    }
  });

  socket.on('offer', ({ targetSocketId, offer }) => {
    socket.to(targetSocketId).emit('offer', { fromSocketId: socket.id, offer });
  });

  socket.on('answer', ({ targetSocketId, answer }) => {
    socket.to(targetSocketId).emit('answer', { fromSocketId: socket.id, answer });
  });

  socket.on('ice-candidate', ({ targetSocketId, candidate }) => {
    socket.to(targetSocketId).emit('ice-candidate', { fromSocketId: socket.id, candidate });
  });

  socket.on('speaking', () => {
    if (socket.channelId) {
      socket.to(socket.channelId).emit('speaking', { socketId: socket.id });
    }
  });

  socket.on('stopped-speaking', () => {
    if (socket.channelId) {
      socket.to(socket.channelId).emit('stopped-speaking', { socketId: socket.id });
    }
  });

  socket.on('leave-channel', async () => {
    if (socket.channelId && socket.userId) {
      await leaveChannel(socket.channelId, socket.userId);
    }
  });

  socket.on('disconnecting', async () => {
    if (socket.channelId && socket.userId) {
      await leaveChannel(socket.channelId, socket.userId);
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

server.listen(PORT, () => {
  if (development) {
    console.log(`Development server with socket.io running on http://localhost:${PORT}`);
  } else {
    console.log(`HTTPS Server with socket.io running on https://peerspace.ipo-servers.net:${PORT}`);
  }
});
