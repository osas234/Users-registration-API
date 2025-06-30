import express from 'express';
import jwt from 'jsonwebtoken';
import pool from '../db.js';
import authenticateToken  from '../Middleware/authMiddleware.js';
import bcrypt from 'bcrypt';
import joi from 'joi';
import multer from 'multer';
import sgMail from '@sendgrid/mail';
// import { useReducer } from 'react';

const router = express.Router();

const signupSchema = joi.object({email: joi.string().email().pattern(/@gmail\.com$/).required(),
password: joi.string().min(6)
    .pattern(/[a-z]/, 'lowercase')
    .pattern(/[A-Z]/, 'uppercase')
    .pattern(/[0-9]/, 'number')
    .pattern(/[^a-zA-Z0-9]/, 'special characters')
    .required(),
    confirmPassword: joi.ref('password'),
    username: joi.string().required()
}).with('password', 'confirmPassword');

const generateAccessToken = (user) => {
    return jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '20m' });
};
const generateRefreshToken = (user) => {
    return jwt.sign({ email: user.email }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d '});
}
router.post('/signup', async (req, res) => {
    const { error } = signupSchema.validate(req.body);
    if (error) return res.status(400).json({msg: error.details[0].message});
    
    const { username, email, password } = req.body;

try {
    const [existing] = await pool.query('SELECT * FROM users WHERE email = ? OR username = ?', [email, username]);
    if (existing.length > 0) return res.status(400).json({msg: 'User already exists'});

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, ?, ?)',[username, email, hashedPassword, 'user', false]);

    res.status(201).json({msg: 'Signup successful'});
} catch (err) {
    console.error(err);
    res.status(500).json({msg: 'Internal server error'});
}
});

// ...signup route...
router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) return res.status(400).json({msg: 'User not found'});

        const user = rows[0];
        // user.lastname 
        if(!user.verified) return res.status(403).json({msg: 'please verify your email before signing in.'});
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({msg: 'Invalid credentials'});

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        await pool.query('UPDATE users SET refresh_token = ? WHERE email = ?', [refreshToken, email]);
        
        res.json({ accessToken, refreshToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Internal server error '});
    }
});

// Email verification route
router.get('/verify/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await pool.query('UPDATE users SET verified = 1 WHERE email = ?', [decoded.email]);
        res.status(200).json({ msg: 'Email verified successfully' });
    } catch (err) {
        console.error(err);
        res.status(400).json({ msg: 'Invalid or expired token' });
    }
});

router.post('/token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({msg: 'Refresh token required '});

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE refresh_token = ?', [refreshToken]);
        if (rows.length === 0) return res.status(401).json({msg: 'Invalid refresh token' });
        
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
            if (err) return res.status(403).json({msg: 'Invalid refresh token' });

            const accessToken = generateAccessToken(user);
            res.json({ accessToken });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({msg: 'Internal server error' });
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage });

router.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({msg: 'No file uploaded' });
    }
    res.status(200).json({msg: 'File uploaded successfully', file: req.file });
});

router.delete('/logout', authenticateToken, async (req, res) => {
    try {
        await pool.query('UPDATE users SET refresh_token = NULL WHERE email = ?', [req.user.email]);
        res.status(200).json({msg: 'Logged out sucessfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({msg: 'Internal server error' });
    }
}); 

router.delete('/delete/me', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE email = ?', [req.user.email]);
        res.status(200).json({ msg: 'User deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Internal server error' });
    }
});

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

router.post('/verify-email', async (req, res) => {
    const { email } = req.body;

    try {
        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h'});

        const msg = {
            to: email,
            from: process.env.SENDGRID_EMAIL, // Your verified sendor
            subject: 'Email Verification',
            text: `Click the link to verify your email: http://localhost:${process.env.PORT}/auth/verify/${verificationToken}`,
            html: `<p>Click the link to verify your email: <a href="http:localhost:${process.env.PORT}/auth/verify/${verificationToken}">Verify Email</a></p>`
        };
        await sgMail.send(msg);
        res.status(200).json({msg: 'Verification email sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({msg: 'Failed to send verifiation email' });
    }
});

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, {expiresIn: '15m' });

        const msg = {
            to: email,
            from: process.env.SENDGRID_EMAIL,
            subject: 'Password Reset',
            text: `Click the link to reset your password: http://localhost:${process.env.PORT}/auth/reset-password/${resetToken}`,
            html: `<p>Click the link to reset your password: <a href="http://localhost:${process.env.PORT}/auth/reset-password/${resetToken}">Reset Password</a></p>`
        };
        await sgMail.send(msg);
        res.status(200).json({msg: 'Password resset email sent' });
    } catch (err) {
        console.error(err);
        res.status(500).json({msg: 'Failed to send password reset email' });
    }
});

router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const hashedPassword = await bcrypt.hash(newPassword, 10);;

        await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, decoded.email]);
        res.status(200).json({msg: 'Password reset successfully' });
    } catch (err) {
        console.error(err);
        res.status(400).json({msg: 'Invalid or expired token'}); 
    }
});

export default router;