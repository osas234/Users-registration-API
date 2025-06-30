import express from 'express';
import authenticateToken from '../Middleware/authMiddleware.js';
import authorizeRole from '../Middleware/roleMiddleware.js';

const router = express.Router();

router.get('/health', (req, res) => {
    res.status(200).json({msg:'OK'});
});

router.get('/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
    res.status(200).json({msg: 'Welcome, Admin! '});
});


router.get('/about', (req, res) => {
    return res.status(200).json({msg: 'About us page'});
});

router.get('/contact', (req, res) => {
    return res.status(200).json({msg: 'Contact us page'});
});

router.get('/FAQ', (req, res) => {
    return res.status(200).json({msg: 'FAQ page'})
});

export default router;