const nodemailer = require('nodemailer');

let transporter;

transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'cogcog9000@gmail.com',
        pass: 'bwun jaxk lgnn leal'
    },
});

module.exports = transporter;