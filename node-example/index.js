const express       = require('express');
const cookieParser  = require('cookie-parser');
const expressSession= require('express-session');
const passport      = require('passport');
const hpga          = require('./hpga');

const app           = express();
const PORT          = process.env.PORT || 8080;

if (process.env['SESSION_SECRET'] == null) {
  console.error('Environment variable SESSION_SECRET is not set');
  process.exit(1);
}

app.use(cookieParser());
app.use(expressSession({
  secret: process.env['SESSION_SECRET'],
  resave: true,
  saveUninitialized: false
}));

// Absorb the authentication routes (see the required module)
app.use(hpga);

app.get('/', (req, res) => res.sendFile(__dirname + '/views/index.html'));

const accountPage = (user) => `
<pre>
ID: ${user.id}
Name: ${user.name}
Email: ${user.email}
<a href="/logout">Log out</a>
</pre>
`;

app.get(
  '/account',
  passport.authenticate('hpga'),
  (req, res) => res.send(accountPage(req.user))
);

const server = app.listen(PORT, () => {
  let { address, family, port } = server.address();
  console.log(`Listening on ${family} address ${address}:${port}`);
});
