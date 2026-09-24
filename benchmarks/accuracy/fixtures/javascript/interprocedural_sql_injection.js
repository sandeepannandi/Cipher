const express = require('express');
const db = require('./db');

function findUserByName(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

function lookup(name) {
    return findUserByName(name);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    const user = lookup(username);
    return res.json(user);
};
