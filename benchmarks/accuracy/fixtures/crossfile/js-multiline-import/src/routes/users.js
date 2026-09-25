import {
    findByName as lookup
} from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(lookup(name));
};
