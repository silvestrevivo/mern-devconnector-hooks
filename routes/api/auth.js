const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');

const User = require('../../models/Users');

// @route   GET api/auth
// @desc    Protected route (check if the user exists)
// @access  Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST api/auth
// @desc    Authenticate user + get token (login)
// @access  Public
router.post('/', [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists()
], async (req, res) => {
  const errors = validationResult(req);
  //if errors
  if(!errors.isEmpty()){
    return res.status(400).json({errors: errors.array()})
  }

  const { email, password } = req.body;

  try {
    // if user doesn't exist
    let user = await User.findOne({ email });
    if(!user){
      return res.status(400).json({errors: [{ msg: 'Invalid credentials'}] });
    }

    // if exist, we need to match the password
    const isMatch = await bcrypt.compare(password, user.password);

    if(!isMatch) {
      return res.status(400).json({errors: [{ msg: 'Invalid credentials'}] });
    }

    // return webtoken from user
    const payload = {
      user: {
        id: user.id
        // this Id comes from DataBase when user is created
      }
    };
    jwt.sign(payload, config.get('jwtSecret'), { expiresIn: 3600 }, (err, token) => {
      if(err) throw err;
      console.log('User logged in');
      res.json({token});
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).send('Server error');
  }

});

module.exports = router;
