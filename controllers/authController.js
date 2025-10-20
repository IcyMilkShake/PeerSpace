const passport = require('../config/passport'); // Import directly

exports.googleAuth = (req, res, next) => {
    passport.authenticate('google', { 
        scope: ['profile', 'email'], 
        prompt: 'select_account' 
    })(req, res, next);
};

exports.googleCallback = (req, res, next) => {
    passport.authenticate('google', { 
        failureRedirect: '/?error=auth_failed' 
    })(req, res, () => {
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.redirect('/?error=session_save_failed');
            }
            res.redirect('/');
        });
    });
};

exports.logout = (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destroy error:', err);
                return res.status(500).json({ error: 'Session destroy failed' });
            }
            res.clearCookie('peerspace.sid');
            res.json({ success: true });
        });
    });
};