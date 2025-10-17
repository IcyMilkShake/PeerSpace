const AWS = require('aws-sdk');

AWS.config.update({
  region: 'ap-southeast-7',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const s3 = new AWS.S3();
const BUCKET_NAME = 'peerspace-database';

module.exports = { s3, BUCKET_NAME };