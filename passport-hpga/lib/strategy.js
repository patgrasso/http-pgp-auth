const Strategy  = require('passport-strategy');
const crypto    = require('crypto');
const pgp       = require('./pgp');

const CHALLENGE_LEN = 64;
const AUTH_HDR_RE   = /^([^ ]*?) (.*)$/

class HPGAStrategy extends Strategy {

  /**
   * Creates new HPGAStrategy
   *
   * @param {function} [options.findKey] called when trying to find a public
   *    key by its ID. Applications that cache public keys can use this to
   *    save a trip on each login to a key server
   * @param {function} [options.onChallenge] called when a challenge is issued
   * @param {function} [getUser] called just before calling success() to
   *    transform a "user" (data like name and email @ stored in a PGP public
   *    key) into a user that the application knows (e.g. findKey user in DB)
   */
  constructor(options, getUser) {
    super();
    this.name = 'hpga';
    this._challenges = {};
    this._findKey = options.findKey;
    this._onChallenge = options.onChallenge;
    this._getUser = getUser;
    this._oneTimeTokens = {};
  }

  /**
   * Generate a new challenge string then store it in memory. If the user has
   * specified option: onChallenge(), call it.
   *
   * @return {string} base64-encoded sequence of CHALLENGE_LEN bytes
   */
  generateChallenge() {
    let newChallenge;

    do {
      newChallenge = crypto.randomBytes(CHALLENGE_LEN).toString('base64');
    } while (this._challenges[newChallenge] === true);

    this._challenges[newChallenge] = true;

    if (typeof this._onChallenge === 'function') {
      this._onChallenge(newChallenge);
    }
    return newChallenge;
  }

  /**
   * Redirect the user to a one-time URL that contains the token. This is to
   * support the CLI client for HPGA (currently the only safe way of
   * authenticating using this method). Users whose agent implements HPGA
   * shouldn't be affected by this, as their agent should redirect them through
   * this URL automatically, so they shouldn't notice a difference.
   *
   * @param {express.Request} req
   * @param {object} user this will be associated with a random token in memory
   *    until the token's URL is accessed, at which point it will be removed
   *    from the cache
   */
  redirectToOneTimeURL(req, user) {
    let token = crypto.randomBytes(24).toString('hex');
    this._oneTimeTokens[token] = user;
    return this.redirect(`${req.path}?token=${token}`);
  }

  /**
   * Handles the case where a POST request leads to the authenticate()
   * middleware. This means the 'Authorization' header should be present and
   * should contain a signed message of a valid challenge that has been
   * recently issued. This checks that all of these assertions are true.
   *
   * @param {express.Request} req
   */
  async handleVerification(req, options) {
    // Split the 'Authorization' header per RFC 7235 into <type> and ...the
    // rest of the string.
    let [ _, type, body ] = req.headers['authorization'].match(AUTH_HDR_RE);

    if (type.toUpperCase() !== 'PGP') {
      return this.fail(null, 400);
    }

    let msg = pgp.readArmored(body);
    let publicKey = null;

    try {
      var signingKeyId = pgp.getSigningKeyId(msg);
    } catch (e) {
      return this.error(e.message);
    }

    // Sometimes apps cache keys (yay!). If so, they may provide a findKey()
    // function for retrieving a full key by its ID.
    if (typeof this._findKey === 'function') {
      try {
        publicKey = await this._findKey(signingKeyId)
      } catch (_) {}
    }
    // Otherwise, try the key server. Note that this may take a while.
    if (publicKey == null) {
      if ((publicKey = await pgp.findKey(signingKeyId)) == null) {
        return this.error(`Could not find public key for ${signingKeyId}`);
      }
    }

    return pgp.verify(msg, publicKey)
      .then(({ user, data }) => {
        if (this._challenges[data] !== true) {
          throw { 'error': 'Message does not contain valid challenge' };
        }
        delete this._challenges[data];
        return user;
      })
      .then((user) => {
        /*
         * If the app specifies a getUser function (in constructor), use it
         * to retrieve the correct user (from the app's perspective) before
         * calling success(). Otherwise, just use the data we obtain from the
         * public key.
         */
        if (typeof this._getUser === 'function') {
          this._getUser(user, (err, userFromApp) => {
            if (err) {
              return this.error(err);
            }
            return this.redirectToOneTimeURL(req, userFromApp);
          });
        } else {
          return this.redirectToOneTimeURL(req, user);
        }
      })
      .catch((err) => this.error(err.error !== undefined ? err.error : err));
  }

  /**
   * Handles the case where a GET request leads to the authenticate(), where
   * req.params.token or req.query.token are also defined. If these aren't
   * defined, you shouldn't be calling this method. Looks up the token in this
   * instance's token store and calls success() with the user associated with
   * that token.
   *
   * @param {express.Request} req
   * @param {string} req.params.token
   * @param {string} req.query.token
   */
  handleTokenClaim(req, options) {
    let token = req.params.token || req.query.token;

    if (token == null) {
      return this.fail(null, 400);
    }

    let user = this._oneTimeTokens[token];

    if (user == null) {
      return this.fail(null, 404);
    }

    delete this._oneTimeTokens[token];
    return this.success(user);
  }

  /**
   * Using req.method to distinguish which phase of authentication we are in,
   * GET requests will lead to a new challenge being issued, while POST
   * requests will check for the 'Authorization' header and verify its contents
   * to make sure that the signed content refers to a valid challenge.
   *
   * User-specified options are referenced for looking up keys by ID and
   * transforming a key's user data into a user object maintained by the
   * application.
   *
   * @override
   * @param {express.Request} req
   */
  async authenticate(req, options) {
    if (req.method === 'POST' && req.headers['authorization']) {
      return this.handleVerification(req, options);

    } else if (req.method === 'POST') {
      return this.fail(null, 400);

    } else if (req.method === 'GET' && (req.params.token || req.query.token)) {
      return this.handleTokenClaim(req, options);

    } else if (req.isAuthenticated()) {
      return this.success(req.user);

    } else if (req.method === 'GET') {
      return this.fail(`PGP challenge="${this.generateChallenge()}"`);
    }

    return this.error(`Unsupported method: ${req.method}`);
  }

}

module.exports = HPGAStrategy;
