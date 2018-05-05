
# Node HPGA Example Server

This is a node server that uses PassportJS and the `passport-hpga` passport
strategy for authentication. See HTTP PGP Authentication documentation for
details on this method of authentication.

## Getting started

In this directory:
```sh
npm install
SESSION_SECRET=<some random string> node index.js &
../bin/hpga-login http://localhost:8080/login
```

If you go to [http://localhost:8080/login](http://localhost:8080/login), you'll
see brief instructions for logging in (basically the last line in the above
block).

