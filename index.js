const express       = require('express');
const cookieParser  = require('cookie-parser');
const {
  ensureLoggedIn,
  applyCookie,
  login,
  logout
}                   = require('./server/session');
const app           = express();
const PORT          = process.env.PORT || 8080;

app.use(cookieParser());

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

app.get('/login', login({ successRedirect: '/account' }), (req, res) => {
  res.sendFile(__dirname + '/views/login.html');
});
app.post('/login', login({ successRedirect: '/account' }));

app.get('/pgp-login/:cookieId', applyCookie('/account'));

app.get('/logout', logout, (req, res) => {
  res.redirect('/');
});

app.get('/account', ensureLoggedIn({ redirect: '/login' }), (req, res) => {
  //res.setCookie();
  res.send(`
<pre>
Name: ${req.user.name}
Email: ${req.user.email}
<a href="/logout">Log out</a>
</pre>
`);
});

const server = app.listen(PORT, () => {
  let { address, family, port } = server.address();
  console.log(`Listening on ${family} address ${address}:${port}`);
});
