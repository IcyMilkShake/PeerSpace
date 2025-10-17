const mongoose = require('mongoose');

const connectDB = async () => {
  if (process.env.VERIFICATION !== 'true') {
    try {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/PeerSpace', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Connected to MongoDB');
    } catch (error) {
      console.error('MongoDB connection error:', error);
      process.exit(1);
    }
  }
};

module.exports = connectDB;