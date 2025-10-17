const nodemailer = require('nodemailer');

let transporter;

if (process.env.NODE_ENV === 'production') {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS,
        },
    });
} else {
    transporter = nodemailer.createTransport({
        streamTransport: true,
        newline: 'unix',
        buffer: true
    });
}

module.exports = transporter;