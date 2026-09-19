const secret = process.env.JWT_SECRET;

function issueToken(user) {
  return { user, token: `jwt.${secret}.${user}` };
}

module.exports = { issueToken };
