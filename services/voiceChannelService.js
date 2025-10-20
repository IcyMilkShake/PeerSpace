const { VoiceChannel, Notification, Post, Comment } = require('../models');
const { emitNotificationCountUpdate } = require('./notificationService');

const channelTimeouts = {};

// Schedules a voice channel for deletion if it remains empty.
function scheduleVoiceChannelDeletion(channelId, io) {
  if (channelTimeouts[channelId.toString()]) {
    console.log(`Deletion timer for channel ${channelId} already exists. Skipping.`);
    return;
  }

  console.log(`Channel ${channelId} is empty. Starting 3-minute deletion timer.`);
  const timeoutId = setTimeout(async () => {
    try {
      const finalCheckChannel = await VoiceChannel.findById(channelId);
      if (finalCheckChannel && finalCheckChannel.participants.length === 0) {
        console.log(`Timer expired for ${channelId}. Deleting channel.`);

        const creatorId = finalCheckChannel.creator;
        const postId = finalCheckChannel.post;
        const commentId = finalCheckChannel.comment;

        await VoiceChannel.findByIdAndDelete(channelId);

        // Create a notification for the creator
        const newNotification = new Notification({
            user: creatorId,
            type: 'voice_channel_deleted',
            post: postId,
            comment: commentId,
        });
        await newNotification.save();

        // Emit a notification count update to the creator
        await emitNotificationCountUpdate(creatorId, io);
        if (postId && !commentId) {
          await Post.findByIdAndUpdate(postId, { $unset: { voiceChannel: "" } });
          io.emit('voice-channel-deleted', { channelId: channelId, postId: postId, commentId: commentId });
        } else if (postId && commentId) {
          await Comment.findByIdAndUpdate(commentId, { $unset: { voiceChannel: "" } });
          io.emit('voice-channel-deleted', { channelId: channelId, postId: postId, commentId: commentId });
        }
        console.log(`Deleted empty voice channel ${channelId}`);
      } else {
        console.log(`Timer expired for ${channelId}, but it is no longer empty. Deletion cancelled.`);
      }
    } catch (error)      {
      console.error(`Error during voice channel auto-deletion for ${channelId}:`, error);
    } finally {
      delete channelTimeouts[channelId.toString()];
    }
  }, 180000); // 3 minutes

  channelTimeouts[channelId.toString()] = timeoutId;
}

module.exports = {
    scheduleVoiceChannelDeletion,
    channelTimeouts
};