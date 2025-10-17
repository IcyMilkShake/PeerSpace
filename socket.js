const { User, VoiceChannel } = require('./models');
const { scheduleVoiceChannelDeletion, channelTimeouts } = require('./services/voiceChannelService');

module.exports = function (io) {
    io.on('connection', (socket) => {
        console.log(`User connected: ${socket.id}`);

        socket.on('join-post-room', (postId) => {
            if (socket.currentPostRoom) {
                socket.leave(socket.currentPostRoom);
                console.log(`Socket ${socket.id} left room ${socket.currentPostRoom}`);
            }
            const roomName = `post-${postId}`;
            socket.join(roomName);
            socket.currentPostRoom = roomName;
            console.log(`Socket ${socket.id} joined room ${roomName}`);
        });

        socket.on('leave-post-room', () => {
            if (socket.currentPostRoom) {
                socket.leave(socket.currentPostRoom);
                console.log(`Socket ${socket.id} left room ${socket.currentPostRoom}`);
                socket.currentPostRoom = null;
            }
        });

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
                    scheduleVoiceChannelDeletion(channelId, io);
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
};