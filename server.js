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
require('dotenv').config();

const { User, Post, Comment } = require('./schema');

const app = express();
const PORT = process.env.PORT || 3000;

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads', 'profile_pics');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

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

    const postsWithComments = await Promise.all(
      posts.map(async (post) => {
        const comments = await Comment.find({ post: post._id })
          .populate('author', '_id name profilePicture') // Ensure _id is populated
          .sort({ createdAt: 1 });

        return {
          id: post._id,
          title: post.title,
          content: post.content,
          author: {
            id: post.author._id,
            name: post.author.name,
            photo: post.author.profilePicture.path || '/default-profile.png'
          },
          createdAt: post.createdAt.toISOString(),
          comments: comments.map(comment => ({
            id: comment._id,
            content: comment.content,
            author: {
              id: comment.author._id,
              name: comment.author.name,
              photo: comment.author.profilePicture.path || '/default-profile.png'
            },
            createdAt: comment.createdAt.toISOString()
          }))
        };
      })
    );

    res.json(postsWithComments);
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Create new post
app.post('/api/posts', isAuthenticated, async (req, res) => {
  try {
    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    const post = new Post({
      title,
      content,
      author: req.user._id
    });

    await post.save();
    await post.populate('author', 'name profilePicture');

    const responsePost = {
      id: post._id,
      title: post.title,
      content: post.content,
      author: {
        id: post.author._id,
        name: post.author.name,
        photo: post.author.profilePicture.path || '/default-profile.png'
      },
      createdAt: post.createdAt.toISOString(),
      comments: []
    };

    res.json(responsePost);
  } catch (error) {
    console.error('Error creating post:', error);
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