const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const passport = require('passport');

router.get('/google', authController.googleAuth);

router.get('/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/?error=auth_failed',
        failureMessage: true
    }),
    authController.googleCallback
);

router.post('/logout', authController.logout);

module.exports = router;