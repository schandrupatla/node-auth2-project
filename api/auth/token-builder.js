const jwt = require('jsonwebtoken')
const { jwtSecret } = require('../secrets/index')

module.exports = function (user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, jwtSecret, options)
}