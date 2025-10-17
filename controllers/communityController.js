const { Community, Post } = require('../models');
const { s3, BUCKET_NAME } = require('../config/s3');
const { v4: uuidv4 } = require('uuid');

exports.createCommunity = async (req, res) => {
    try {
        const { name, description } = req.body;

        if (!name || name.trim().length < 3) {
            return res.status(400).json({ error: 'Community name must be at least 3 characters long.' });
        }

        const existingCommunity = await Community.findOne({ name: new RegExp(`^${name.trim()}$`, 'i') });
        if (existingCommunity) {
            return res.status(409).json({ error: 'A community with this name already exists.' });
        }

        const newCommunity = new Community({
            name: name.trim(),
            description: description || '',
            owner: req.user._id,
            members: [req.user._id]
        });

        if (req.files) {
            const uploadToS3 = async (file, folder) => {
                const key = `${folder}/${uuidv4()}-${file.originalname}`;
                const params = {
                    Bucket: BUCKET_NAME,
                    Key: key,
                    Body: file.buffer,
                    ContentType: file.mimetype,
                    ACL: 'public-read',
                };
                const result = await s3.upload(params).promise();
                return { path: result.Location, contentType: file.mimetype };
            };

            if (req.files.profilePicture) {
                newCommunity.profilePicture = await uploadToS3(req.files.profilePicture[0], 'community_profile_pics');
            }
            if (req.files.bannerPicture) {
                newCommunity.bannerPicture = await uploadToS3(req.files.bannerPicture[0], 'community_banner_pics');
            }
        }

        await newCommunity.save();
        res.status(201).json(newCommunity);

    } catch (error) {
        console.error('Error creating community:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to create community.' });
    }
};

exports.getAllCommunities = async (req, res) => {
    try {
        const communities = await Community.find({})
            .populate('owner', 'username displayName')
            .select('name description profilePicture bannerPicture members owner createdAt')
            .sort({ createdAt: -1 });

        const communitiesWithMemberCount = communities.map(c => ({
            ...c.toObject(),
            memberCount: c.members.length
        }));

        res.json(communitiesWithMemberCount);
    } catch (error) {
        console.error('Error fetching communities:', error);
        res.status(500).json({ error: 'Failed to fetch communities.' });
    }
};

exports.getCommunityById = async (req, res) => {
    try {
        const { communityId } = req.params;
        const community = await Community.findById(communityId)
            .populate('owner', 'username displayName profilePicture')
            .populate('members', 'username displayName profilePicture');

        if (!community) {
            return res.status(404).json({ error: 'Community not found.' });
        }

        res.json(community);
    } catch (error) {
        console.error('Error fetching community:', error);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ error: 'Invalid community ID format.' });
        }
        res.status(500).json({ error: 'Failed to fetch community.' });
    }
};

exports.updateCommunity = async (req, res) => {
    try {
        const { communityId } = req.params;
        const { name, description } = req.body;

        const community = await Community.findById(communityId);

        if (!community) {
            return res.status(404).json({ error: 'Community not found.' });
        }

        if (community.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'You are not authorized to edit this community.' });
        }

        if (name && name.trim().length >= 3) {
            const existingCommunity = await Community.findOne({ name: new RegExp(`^${name.trim()}$`, 'i'), _id: { $ne: communityId } });
            if (existingCommunity) {
                return res.status(409).json({ error: 'A community with this name already exists.' });
            }
            community.name = name.trim();
        }

        if (description) {
            community.description = description;
        }

        if (req.files) {
            const uploadToS3 = async (file, folder) => {
                const key = `${folder}/${uuidv4()}-${file.originalname}`;
                const params = {
                    Bucket: BUCKET_NAME,
                    Key: key,
                    Body: file.buffer,
                    ContentType: file.mimetype,
                    ACL: 'public-read',
                };
                const result = await s3.upload(params).promise();
                return { path: result.Location, contentType: file.mimetype };
            };

            if (req.files.profilePicture) {
                community.profilePicture = await uploadToS3(req.files.profilePicture[0], 'community_profile_pics');
            }
            if (req.files.bannerPicture) {
                community.bannerPicture = await uploadToS3(req.files.bannerPicture[0], 'community_banner_pics');
            }
        }

        await community.save();
        res.json(community);

    } catch (error) {
        console.error('Error updating community:', error);
        res.status(500).json({ error: 'Failed to update community.' });
    }
};

exports.joinCommunity = async (req, res) => {
    try {
        const { communityId } = req.params;
        const userId = req.user._id;

        const community = await Community.findByIdAndUpdate(
            communityId,
            { $addToSet: { members: userId } },
            { new: true }
        );

        if (!community) {
            return res.status(404).json({ error: 'Community not found.' });
        }

        res.json({ success: true, message: 'Successfully joined the community.' });
    } catch (error) {
        console.error('Error joining community:', error);
        res.status(500).json({ error: 'Failed to join community.' });
    }
};

exports.leaveCommunity = async (req, res) => {
    try {
        const { communityId } = req.params;
        const userId = req.user._id;

        const community = await Community.findById(communityId);

        if (!community) {
            return res.status(404).json({ error: 'Community not found.' });
        }

        if (community.owner.equals(userId)) {
            return res.status(400).json({ error: 'The owner cannot leave the community.' });
        }

        community.members.pull(userId);
        await community.save();

        res.json({ success: true, message: 'Successfully left the community.' });
    } catch (error) {
        console.error('Error leaving community:', error);
        res.status(500).json({ error: 'Failed to leave community.' });
    }
};

exports.deleteCommunity = async (req, res) => {
    try {
        const { communityId } = req.params;
        const userId = req.user._id;

        const community = await Community.findById(communityId);

        if (!community) {
            return res.status(404).json({ error: 'Community not found.' });
        }

        if (community.owner.toString() !== userId.toString()) {
            return res.status(403).json({ error: 'You are not authorized to delete this community.' });
        }

        // Delete all posts within the community
        await Post.deleteMany({ community: communityId });

        await Community.findByIdAndDelete(communityId);

        res.json({ success: true, message: 'Community deleted successfully.' });
    } catch (error) {
        console.error('Error deleting community:', error);
        res.status(500).json({ error: 'Failed to delete community.' });
    }
};