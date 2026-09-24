import express from 'express';
import findByName from '../services/users';

const router = express.Router();

router.get('/users/search', (req, res) => {
    const { name } = req.query;
    return res.json(findByName(name));
});

export default router;
