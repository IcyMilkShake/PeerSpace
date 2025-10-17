const express = require('express');
const session = require('express-session');
const passport = require('passport');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require("socket.io");
require('dotenv').config();

const connectDB = require('./config/db');
const configurePassport = require('./config/passport');
const allRoutes = require('./routes');
const configureSocket = require('./socket');

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

// Connect to MongoDB
connectDB();

// Passport configuration
configurePassport(passport);

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
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  },
};

if (process.env.VERIFICATION !== 'true') {
  sessionConfig.store = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/PeerSpace',
    touchAfter: 24 * 3600,
    ttl: 24 * 60 * 60
  });
}

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

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/', allRoutes);
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});
app.get('/inbox', (req, res) => {
    res.sendFile(path.join(__dirname, 'inbox.html'));
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

app.set('socketio', io);

// Configure Socket.IO
configureSocket(io);

console.log(`Attempting to start server on port ${PORT}`);
server.listen(PORT, () => {
  if (development) {
    console.log(`Development server with socket.io running on http://localhost:${PORT}`);
  } else {
    console.log(`HTTPS Server with socket.io running on https://peerspace.ipo-servers.net:${PORT}`);
  }
});