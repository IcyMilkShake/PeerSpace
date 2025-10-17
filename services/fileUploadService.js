const fs = require('fs');
const path = require('path');
const ffmpeg = require('fluent-ffmpeg');
const { v4: uuidv4 } = require('uuid');
const { s3, BUCKET_NAME } = require('../config/s3');
const { Comment, VoiceChannel } = require('../models');

const processedDir = path.join(__dirname, '../processed');

async function processAndUploadFile(file) {
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
        fs.unlinkSync(file.path);
        fs.unlinkSync(outputPath);
        return {
            url: result.Location,
            fileType: 'video'
        };
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
        fs.unlinkSync(file.path);
        return {
            url: result.Location,
            fileType: 'image'
        };
    }
    return null;
}

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

module.exports = {
    processAndUploadFile,
    deleteCommentAndChildren,
};