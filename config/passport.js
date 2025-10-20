const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const https = require('https');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { User } = require('../models');
const { s3, BUCKET_NAME } = require('./s3');

const development = process.env.NODE_ENV !== 'production';

// Helper functions
async function downloadProfilePicture(url, filename) {
    return new Promise((resolve, reject) => {
        https.get(url, (response) => {
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', async () => {
                const buffer = Buffer.concat(chunks);
                const ext = path.extname(url).split('?')[0] || '.png';
                const key = `profile_pics/${filename}${ext}`;
                const params = {
                    Bucket: BUCKET_NAME,
                    Key: key,
                    Body: buffer,
                    ContentType: response.headers['content-type'],
                    ACL: 'public-read',
                };
                try {
                    const result = await s3.upload(params).promise();
                    resolve(result.Location);
                } catch (error) {
                    reject(error);
                }
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
}

async function generateUniqueUsername(email) {
    let username = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_.]/g, '');
    if (username.length < 3) {
        username = `user_${username}${uuidv4().substring(0, 8)}`;
    }
    username = username.substring(0, 20);

    let user = await User.findOne({ username });
    while (user) {
        const randomSuffix = uuidv4().substring(0, 4);
        username = `${username.substring(0, 15)}_${randomSuffix}`;
        user = await User.findOne({ username });
    }
    return username;
}

// Configure passport directly
const CALLBACK_URL = development
    ? 'http://localhost:8082/auth/google/callback'
    : 'https://peerspace.ipo-servers.net/auth/google/callback';

if (process.env.VERIFICATION !== 'true') {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: CALLBACK_URL
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ googleId: profile.id });
            const profilePictureUrl = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

            if (user) {
                user.lastLogin = new Date();
                if (!user.displayName) {
                    user.displayName = profile.displayName;
                }
                const hasCustomProfilePic = user.profilePicture.path && !user.profilePicture.path.includes('googleusercontent.com');

                if (!hasCustomProfilePic && profilePictureUrl) {
                    try {
                        const filename = `google_${uuidv4()}`;
                        const s3Url = await downloadProfilePicture(profilePictureUrl, filename);
                        user.profilePicture = { path: s3Url, contentType: 'image/png' };
                    } catch (error) {
                        console.error('Error downloading profile picture:', error);
                    }
                }
                await user.save();
                return done(null, user);
            } else {
                let profilePicturePath = null;
                if (profilePictureUrl) {
                    try {
                        const filename = `google_${uuidv4()}`;
                        profilePicturePath = await downloadProfilePicture(profilePictureUrl, filename);
                    } catch (error) {
                        console.error('Error downloading profile picture for new user:', error);
                    }
                }

                const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
                const username = await generateUniqueUsername(email);

                const newUser = new User({
                    googleId: profile.id,
                    username: username,
                    displayName: profile.displayName,
                    email: email,
                    profilePicture: { path: profilePicturePath, contentType: 'image/png' }
                });

                await newUser.save();
                return done(null, newUser);
            }
        } catch (error) {
            console.error('Error in Google Strategy:', error);
            return done(error, null);
        }
    }));
}

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        console.log('deserializeUser for', id);
        done(null, user);
    } catch (err) {
        console.error('>>> DESERIALIZE ERROR:', err);
        done(err, null);
    }
});

// Export the configured passport instance
module.exports = passport;