const express       = require('express');
const passport      = require('passport');
const HPGAStrategy  = require('passport-hpga');
const openpgp       = require('openpgp');
const crypto        = require('crypto');
const router        = express.Router();

const keyCache      = {};
const users         = {};

// Setup the HPGA strategy
passport.use(new HPGAStrategy({

  // use keyCache to save a trip to your neighborhood key server
  findKey: (keyId) => openpgp.key.read(keyCache[keyId]).keys[0]

}, (keydata, cb) => {
  let user = users[keydata.email];

  // Create user if user is not known
  if (user == null) {
    user = Object.assign({}, keydata);
    user.id = crypto.randomBytes(16).toString('hex');
    users[keydata.email] = user;
  }

  // Cache the user's public key
  keyCache[keydata.publicKeyId] = keydata.publicKey
  return cb(null, user);
}));

// Serialize using the user's email (unique identifier, I suppose)
passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((id, done) => done(null, users[id]));

router.use(passport.initialize());
router.use(passport.session());

const authenticate = passport.authenticate('hpga', {
  successRedirect: '/account',

  // This forces passport to use next() so that we can send a file explaining
  // how to authenticate via CLI instead of just "Unauthorized"
  failWithError: true
});

// Returns a 401 response with instructions on how to log in. See
// HPGA#authenticate() for more on this.
router.get(
  '/login',
  authenticate,
  (req, res) => res.sendFile(__dirname + '/views/login.html'),
  (err, req, res, next) => res.sendFile(__dirname + '/views/login.html')
);

// Expects the 'Authorization' header to contain 'PGP <challenge sig>'.
// HPGAStrategy will take care of this. We just need to make sure the route
// exists.
router.post('/login', passport.authenticate('hpga'));

router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

module.exports = router;
