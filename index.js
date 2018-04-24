const express       = require('express');
const cookieParser  = require('cookie-parser');
const app           = express();
const PORT          = process.env.PORT || 8080;
const AUTH_COOKIE   = 'pgp-auth-test-cookie';
const sessions      = {};
const DEF_SESSION   = {
  email: null,
  name: null,
  favColor: null,
  _cookie: null
};

function genAuthenticateHeader(realm) {
  return `PGP realm="Test stuff" nonce=`;
}

app.use(cookieParser());

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

/**
 * Check to see if the user has already authenticated and has a valid session
 * cookie. If so, attach their user info to req.user. Otherwise, send a 401
 * "Unauthorized" response with the WWW-Authenticate header set to PGP
 */
app.use('/account', (req, res, next) => {
  if (req.cookies[AUTH_COOKIE] != null && sessions[AUTH_COOKIE] != null) {
    req.user = sessions[AUTH_COOKIE];
    return next();
  }
  if (req.method.toUpperCase() === 'POST') {
    // TODO: check PGP signature on the nonce we still need to implement
  }
  res.setHeader('WWW-Authenticate', 'PGP realm="Testing PGP Auth"');
  res.status(401);
  res.send('<pre>Unauthorized</pre>');
});

app.get('/account', (req, res) => {
  console.log(req.cookies);
  res.send('Nothing to see here');
});

const server = app.listen(PORT, () => {
  let { address, family, port } = server.address();
  console.log(`Listening on ${family} address ${address}:${port}`);
});
