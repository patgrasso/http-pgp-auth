# HTTP PGP Authentication: Flow

This document serves to outline the authentication flow for
HTTP PGP Authentication. This is a very general overview and **not** a
technical specification.

1. User goes a site's login page (e.g. https://example.com/login).

2. The site specifies PGP Authentication as an option for logging in, along
   with a URL that the user can use with hpga-login(1).

3. The user copies that URL (e.g. https://example.com/login/pgp) and runs
   ```sh
   $ hpga-login https://example.com/login/pgp
   ```

4. hpga-login(1) makes a GET request to the specified URL:
   ```
   GET /login/pgp HTTP/1.1
   Host: example.com
   ```

5. Since the user is not logged in, the server responds with a 401
   (Unauthorized) status along with the `WWW-Authenticate` header:
   ```
   HTTP/1.1 401 Unauthorized
   Date: Thu, 03 May 2018 18:44:07 GMT
   Content-Type: text/html; charset=UTF-8
   WWW-Authenticate: PGP realm="https://example.com" challenge="CPCWj2NcWAU..."
   ```

6. hpga-login(1) generates a PGP signature of the challenge data (the
   equivalent of `echo -n <challenge> | gpg -s`) and sends this back to the
   server within the `Authorization` header of a POST request to the same URL:
   ```
   POST /login/pgp HTTP/1.1
   Host: example.com
   Authorization: PGP -----BEGIN PGP MESSAGE-----
    
    I==rif3M1YpWNNARQe3eS+arln3Bi/Iy38pf7w/yHMy1iFxtVH7EIeHB1PvCOWaS
    s5W9UXMWeak344B6rsVoGJ5a/NnYh4CZyKyK67lFEuwbkTJWX=CQqrNRGOPAPS0Z
    2YcIYfFEkqGKBcc3=5lXvYLF/6UPU4s8uw80cOSGclFa0DfXSWpKP8mZjkGGOQMO
    cdjsJeohx+TnZ/omcSrbFuupMedUa9jxWv+Oibiu5pWUj48bZLTiIbQ62EE2D25Z
    +UEWKdPpOrQWVQRh6UuwIjUUCLTnyM3Ra9kZqA35HJ6W9Eaz=KS0bkFwvrxwAOs1
    ezyQF2PaVIO4Ya=+s6V4e5FfyPyKWpp4LlUXQhsCZVFVeRyp08bYJ5AMh8C7WZI+
    z1vqfvqXjhDpMzxD19EMF6MMKheLGLf2C6Z4C5O8sbMxJgZcI/lpPwZTrwu9tNPx
    Ewq1lEFGsKn/InGFZ6IfPvtj26M062xviBPHobyTGOO+FoaPtIzXBWtf4Jp2OPr/
    /jxumUR+=q=yNjl=upifJy58+yMJI/VoXb1i0UhxE6hZ/yzACAxW0kkWOmf40f1o
    YpnPno/d2D2mQgBXzf9c6euC3GfB6FSwp5WaolABj7cgCSr9Fj39gm9NrCaYFMy2
    E7g6NZv0ieRk0R/qLVd9XQw+i+ZgmAtIXDYSp8EbW9hK9qU+MZWvP9Iwww9Vp3=O
    Nbuy/2Pm6ciqRFy+XYeJ/EiYHcQwG/zjLarB/7=c7KiZMKQNyXZhBwofIQkKki0W
    7islDpBF8H0C+NuPYc0j5ZTO=0Df=WRy
    =UxqY
    -----END PGP MESSAGE-----
   ```

   **Note:** this PGP message MUST contain the signer's key ID, the signature
   of the challenge, and the challenge itself (`gpg -s` does all of this
   automatically).

7. The server may need to query a PGP key server to find the public key
   associated with the key ID in the signature. Once obtained, the server
   should cache this public key to avoid overloading PGP key servers. The
   server will verify that this signature is valid per the public key obtained
   from a key server (or from the cache). Depending on the application, the
   server may respond differently.

   Some examples of what the server may respond with:
   - 303 "See Other" with the `Location` header set to a one-time url that the
     user can use to initiate a session (the one-time url will respond with a
     `Set-Cookie` header).

   - 200 "OK" with a `Set-Cookie` header (though this would be unusual).

   - 401 "Unauthorized" if the signature is not valid or the public key has
     expired/been revoked.

   The first case (redirection with 303) might look like the following:
   ```
   HTTP/1.1 303 See Other
   Date: Thu, 03 May 2018 18:44:10 GMT
   Content-Type: text/html; charset=UTF-8
   Location: https://example.com/login/pgp/8dabf2af4f6d0661dc9f99db1ab49249
   ```
   When hpga-login(1) sees this, it will attempt to open the URL in the user's
   browser to initiate a session.

