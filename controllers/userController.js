const { User, Post, Comment } = require('../models');
const mongoose = require('mongoose');
const { populatePostDetails } = require('../services/utils');
const crypto = require('crypto');
const transporter = require('../config/nodemailer');
const { s3, BUCKET_NAME } = require('../config/s3');
const { v4: uuidv4 } = require('uuid');

const development = process.env.NODE_ENV !== 'production';

exports.getCurrentUser = (req, res) => {
    if (req.isAuthenticated() && req.user) {
        const { _id, username, displayName, email, profilePicture, bannerPicture, description, createdAt, theme, audioSettings, credibility, emailVerified, hideCredibilityNotification } = req.user;
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
            audioSettings: audioSettings,
            credibility,
            emailVerified,
            hideCredibilityNotification
        });
    } else {
        return res.status(401).json({ error: 'Not authenticated' });
    }
};

exports.searchUsers = async (req, res) => {
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
};

exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('username displayName profilePicture bannerPicture description createdAt credibility');
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
            createdAt: user.createdAt,
            credibility: user.credibility || '0'
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
};

exports.getUserByUsername = async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('username displayName profilePicture bannerPicture description createdAt credibility');
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
            createdAt: user.createdAt,
            credibility: user.credibility || '0'
        });
    } catch (error) {
        console.error('Error fetching user by username:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
};

exports.getUserContent = async (req, res) => {
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
                const unsortedPosts = await Post.find({ _id: { $in: ids } }).populate('author', 'username displayName profilePicture').populate('community', 'name _id').populate('voiceChannel');
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
                const unsortedPosts = await Post.find({ _id: { $in: ids } }).populate('author', 'username displayName profilePicture').populate('community', 'name _id').populate('voiceChannel');
                sortedPosts = ids.map(id => unsortedPosts.find(p => p._id.equals(id)));
            } else {
                const sortOption = (sortBy === 'oldest') ? { createdAt: 1 } : { createdAt: -1 };
                sortedPosts = await Post.find({ author: authorId })
                    .populate('author', 'username displayName profilePicture')
                    .populate('community', 'name _id')
                    .populate('voiceChannel')
                    .sort(sortOption);
            }

            const postsWithDetails = await Promise.all(
                sortedPosts.map(post => populatePostDetails(post, currentUserId))
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
};

exports.updateUserDescription = async (req, res) => {
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
};

exports.updateUserDisplayName = async (req, res) => {
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
};

exports.sendVerificationEmail = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.emailVerified) {
            return res.status(400).json({ error: 'Email is already verified' });
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.emailVerificationToken = verificationToken;
        user.emailVerificationExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const verificationUrl = development
            ? `http://localhost:8082/api/user/verify-email/${verificationToken}`
            : `https://peerspace.ipo-servers.net/api/user/verify-email/${verificationToken}`;

        const mailOptions = {
            from: "Peerspace <noreply@ipo-servers.net>", // replace with your "from" email address
            to: user.email,
            subject: 'Verify Your Email for Our Forum',
            html: `<p>Please click this link to verify your email address: <a href="${verificationUrl}">${verificationUrl}</a></p>`,
            text: `Please copy and paste this URL into your browser to verify your email: ${verificationUrl}`
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Verification email sent.' });

    } catch (error) {
        console.error('Error sending verification email:', error);
        res.status(500).json({ error: 'Failed to send verification email.' });
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('<h1>Invalid or expired verification link.</h1><p>Please request a new verification email.</p>');
        }

        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();

        res.send('<h1>Email successfully verified!</h1><p>You can now close this tab and return to the forum.</p>');

    } catch (error) {
        console.error('Error verifying email:', error);
        res.status(500).send('<h1>Error</h1><p>An error occurred during email verification. Please try again later.</p>');
    }
};

exports.hideCredibilityNotification = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        user.hideCredibilityNotification = true;
        await user.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Error hiding credibility notification:', error);
        res.status(500).json({ error: 'Failed to update user settings.' });
    }
};

exports.updateUsername = async (req, res) => {
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
};

exports.updateUserTheme = async (req, res) => {
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
};

exports.uploadProfilePicture = async (req, res) => {
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
};

exports.updateAudioSettings = async (req, res) => {
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
};

exports.uploadBannerPicture = async (req, res) => {
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
};