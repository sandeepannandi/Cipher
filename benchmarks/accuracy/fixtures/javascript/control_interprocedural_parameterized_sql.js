const express = require('express');
const db = require('./db');

function findUserByName(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function lookup(name) {
    return findUserByName(name);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    const user = lookup(username);
    return res.json(user);
};
