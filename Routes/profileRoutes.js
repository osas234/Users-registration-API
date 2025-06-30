import express from 'express';
import authenticateToken from '../Middleware/authMiddleware.js';
import pool from '../db.js';

const router = express.Router();
// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT username, email, role, verified, created_at FROM users WHERE email = ?', [req.user.email]);
        if (rows.length === 0) return res.status(404).json({ msg: 'User not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Internal server error' });
    }
});

// Update user profile (username and email)
router.put('/profile', authenticateToken, async (req, res) => {
    const { username, email } = req.body;
    try {
        await pool.query('UPDATE users SET username = ?, email = ? WHERE email = ?', [username, email, req.user.email]);
        res.json({ msg: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Internal server error' });
    }
});

export default router;