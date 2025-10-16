const mongoose = require('mongoose');

// Checks if the number of attachments is within the limit.
function arrayLimit(val) {
  return val.length <= 15;
}

// User Schema
const userSchema = new mongoose.Schema({
  googleId: {
    type: String,
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: /^[a-zA-Z0-9_.]+$/,
    minLength: 3,
    maxLength: 20
  },
  displayName: {
    type: String,
    required: true,
    maxLength: 50
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
  bannerPicture: {
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
  },
  theme: {
    type: String,
    default: 'dark'
  },
  friends: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  audioSettings: {
    inputDevice: { type: String, default: 'default' },
    outputDevice: { type: String, default: 'default' },
    micVolume: { type: Number, default: 100 }
  },
  credibility: {
    type: Number,
    default: 0
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  dailyCredibility: {
    value: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
  },
  hideCredibilityNotification: {
    type: Boolean,
    default: false
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
    required: false,
    maxlength: 2500
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  linkPreview: {
    url: String,
    title: String,
    description: String,
    image: String,
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
  attachments: {
    type: [{
      url: { type: String, required: true },
      fileType: { type: String, required: true, enum: ['image', 'video'] }
    }],
    validate: [arrayLimit, '{PATH} exceeds the limit of 15']
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
  }],
  voiceChannel: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'VoiceChannel',
    default: null
  },
  community: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Community',
    default: null
  },
  answeredComment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    default: null
  }
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
  linkPreview: {
    url: String,
    title: String,
    description: String,
    image: String,
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  voiceChannel: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'VoiceChannel',
    default: null
  },
  reports: [{
    reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reasonType: { type: String, required: true },
    reasonDetails: { type: String },
    reportedAt: { type: Date, default: Date.now }
  }],
  credibilityAwardedForLikes: {
    type: Boolean,
    default: false
  },
  credibilityAwardedForAnswer: {
    type: Boolean,
    default: false
  }
});

// Community Schema
const communitySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  description: {
    type: String,
    maxlength: 500
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
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
  bannerPicture: {
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
  }
});

// Create models
const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Community = mongoose.model('Community', communitySchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  user: { // The user who receives the notification
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sender: { // The user who triggered the notification
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  type: { // e.g., 'mention', 'like', 'comment'
    type: String,
    required: true,
    enum: ['mention', 'voice_channel_deleted']
  },
  post: { // The post where the event happened
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true
  },
  comment: { // Optional: The comment where the event happened
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment'
  },
  read: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Friend Request Schema
const friendRequestSchema = new mongoose.Schema({
  requester: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'declined'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

// VoiceChannel Schema
const voiceChannelSchema = new mongoose.Schema({
  post: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: false // A voice channel can be in a post or a comment
  },
  comment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    required: false
  },
  name: {
    type: String,
    required: true,
    default: 'Voice Channel'
  },
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const VoiceChannel = mongoose.model('VoiceChannel', voiceChannelSchema);

module.exports = {
  User,
  Post,
  Comment,
  Notification,
  FriendRequest,
  VoiceChannel,
  Community
};