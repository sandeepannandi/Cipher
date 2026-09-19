const secret = "dev-secret";

function issueToken(user) {
  return { user, token: `jwt.${secret}.${user}` };
}

module.exports = { issueToken };
