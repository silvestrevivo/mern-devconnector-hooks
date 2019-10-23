const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
  // Get token from the header
  const token = req.header('x-auth-token');

  // Check if not token
  if(!token){
    return res.status(401).json({msg: 'No token, authorization denied'});
  }

  // Verify token
  try {
    const decoded = jwt.verify(token, config.get('jwtSecret'));
    // if is found, we assing the user from that token
    // for that we create a user property in the req object
    // decoded.user => { id: '5db0a1d82cd59f063093df35' }
    req.user = decoded.user;
    next();
  } catch (error) {
    res.status(401).json({msg: 'Token is not valid'});
  }
}
