const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
  googleId: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  profilePicture: {
    path: {
      type: String,
      default: null
    },
    contentType: {
      type: String,
      default: 'image/png'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  description: {
    type: String,
    default: '',
    maxlength: 500 // Optional: set a max length for the description
  }
}, { collection: 'User' });

// Post Schema
const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    maxlength: 80
  },
  content: {
    type: String,
    required: true,
    maxlength: 2500
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  postType: {
    type: String,
    enum: ['normal', 'question', 'guide', 'poll'],
    default: 'normal'
  },
  pollOptions: [{
    option: { type: String, required: true, maxlength: 75 },
    votes: { type: Number, default: 0 }
  }],
  reports: [{
    reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reasonType: { type: String, required: true },
    reasonDetails: { type: String },
    reportedAt: { type: Date, default: Date.now }
  }],
  usersWhoVoted: [{ // To track who voted on a poll and for which option
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    optionIndex: { type: Number, required: true }
  }]
});

// Comment Schema
const commentSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true,
    maxlength: 1000
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  post: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true
  },
  parentComment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    default: null // Optional: for top-level comments or if not a reply
  },
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
});

// Create models
const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Comment = mongoose.model('Comment', commentSchema);

module.exports = {
  User,
  Post,
  Comment
};