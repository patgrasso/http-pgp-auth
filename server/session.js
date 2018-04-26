const crypto        = require('crypto');
const pgp           = require('./pgp');

const AUTH_COOKIE   = 'pgp-auth-test-cookie';
const COOKIE_BYTES  = 32;
const NONCE_BYTES   = 64;
const EXPIRED       = new Date(0).toUTCString();
const DEF_SESSION   = {
  email: null,
  name: null,
  favColor: null,
  _cookie: null
};

const sessions      = {};
const nonces        = {};

const unclaimedCookies = {};

function generateWWWAuthenticateHeader() {
  let nonce = crypto.randomBytes(NONCE_BYTES).toString('base64');
  nonces[nonce] = true;
  return `PGP realm="Testing PGP Auth", nonce=${nonce}`;
}

const AUTH_HDR_RE   = /^([^ ]*?) (.*)$/

function parseAuthHeader(headerValue) {
  let match = headerValue.match(AUTH_HDR_RE);

  if (match == null || match.length < 3) {
    return null;
  }

  let [ msgHdr, msgFtr ] = match[2].match(/(\-{5}[ A-Z]*\-{5})/g);
  let body = match[2]
    .replace(msgHdr, '')
    .replace(msgFtr, '')
    .replace(/ /g, '\n');

  return {
    type: match[1],
    data: `${msgHdr}${body}${msgFtr}`
  };
}

function applyCookie(redirectUrl) {
  return function (req, res, next) {
    let cid = req.params.cookieId;

    res.setHeader('Set-Cookie', `${AUTH_COOKIE}=${unclaimedCookies[cid]}; Path=/`);
    delete unclaimedCookies[cid];
    res.redirect(redirectUrl);
  }
}

function logout(req, res, next) {
  res.setHeader('set-cookie', `${AUTH_COOKIE}=null; Expires=${EXPIRED}`);
  next();
}

function login(options={}) {
  let failRedirect    = options.failRedirect || null;
  let successRedirect = options.successRedirect || null;
  let failText        = options.failText || 'Unauthorized';
  let successText     = options.successText || 'Successfully logged in';

  return async function (req, res, next) {
    if (req.method.toUpperCase() === 'POST') {
      let authHeader;

      if ((authHeader = req.headers['authorization']) == null) {
        // TODO: use failRedirect or failText
        return next('No eggs for you');
      }
      try {
        let { type: authType, data: authData } = parseAuthHeader(authHeader);

        if (authType !== 'PGP') {
          return next('No eggs for you');
        }

        // Once we verify the signature, we need to check that the data is
        // actually a valid nonce (one that we've issued).
        var { data, user } = await pgp.verify(authData);

        if (nonces[data.toString().trim()] !== true) {
          throw new Error('Invalid signature');
        }
      } catch (e) {
        return next(e.error || e.message);
      }

      // Assume successful login
      let cookie = crypto.randomBytes(COOKIE_BYTES / 2).toString('hex');
      let cid = crypto.randomBytes(COOKIE_BYTES / 2).toString('hex');

      unclaimedCookies[cid] = cookie;
      sessions[cookie] = Object.assign({}, DEF_SESSION);
      Object.assign(sessions[cookie], user);

      res.setHeader('Set-Cookie', `${AUTH_COOKIE}="${cookie}"`);
      res.setHeader('x-cookie-url', cid);

      if (successRedirect) {
        return res.redirect(successRedirect);
      }
      return res.send(`<pre>${successText}</pre>`);
    }

    let cookie = req.cookies[AUTH_COOKIE];
    if (cookie != null && sessions[cookie] != null) {
      if (successRedirect != null) {
        return res.redirect(successRedirect);
      }
      return res.send(`<pre>${successText}</pre>`);
    }
    res.status(401);
    res.setHeader('WWW-Authenticate', generateWWWAuthenticateHeader());
    return next();
  }
}

function ensureLoggedIn(options={}) {
  let redirect  = options.redirect || null;
  let failText  = options.failText || 'Unauthorized';

  return function (req, res, next) {
    if (req.cookies[AUTH_COOKIE] != null && sessions[req.cookies[AUTH_COOKIE]] != null) {
      req.user = sessions[req.cookies[AUTH_COOKIE]];
      return next();
    } else if (req.cookies[AUTH_COOKIE] != null) {
      res.setHeader('set-cookie', `${AUTH_COOKIE}=null; Expires=${EXPIRED}`);
    }
    if (redirect != null) {
      return res.redirect(redirect);
    }
    res.status(401);
    res.setHeader('WWW-Authenticate', 'PGP realm="Testing PGP Auth"');
    return res.send(`<pre>${failText}</pre>`);
  };
}

module.exports = { ensureLoggedIn, login, applyCookie, logout };
