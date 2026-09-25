import {
    findByName
} from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};
