const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const auth = require('../../middleware/auth');

// user model
const User = require('../../models/User');

// @route   POST api/auth
// @desc    authenticate user
// @access  public
router.post('/', (req, res) => {
  const { email, password } = req.body;

  // simple validation
  if (!email || !password) {
    return res.status(400).json({ msg: 'Please enter all fields' });
  }

  // check for existing user
  User.findOne({ email: email }).then((user) => {
    if (!user) return res.status(400).json({ msg: 'User does not exist' });

    // validate password
    bcrypt
      .compare(password, user.password)
      .then((isMatch) => {
        if (!isMatch) {
          return res.status(400).json({
            msg: 'Invalid credentials',
          });
        }

        jwt.sign(
          { id: user.id },
          process.env.JWT_SECRET,
          { expiresIn: 3600 },
          (err, token) => {
            if (err) throw err;
            return res.json({
              token: token,
              user: {
                id: user.id,
                name: user.name,
                email: user.email,
              },
            });
          }
        );
      })
      .catch((err) => `Unable to authenticate user: ${err}`);
  });
});

// @route   POST api/auth/user
// @desc    get user data
// @access  private
router.get('/user', auth, (req, res) => {
  User.findById(req.user.id)
    .select('-password')
    .then((user) => res.json(user));
});

module.exports = router;
