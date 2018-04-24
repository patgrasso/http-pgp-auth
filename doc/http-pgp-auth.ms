\""""""""""""""""""""""""" HTTP PGP Authentication """"""""""""""""""""""""/
\" Instructions for document generation:                                  "/
\"   Generate tty:    groff -R -Tascii -ms <file>.ms | less               "/
\"   Generate plain:  groff -R -Tascii -P-cbou -ms <file>.ms > <out>.txt  "/
\"   Generate PDF:    groff -R -Tpdf -ms <file>.ms > <out>.pdf            "/
\"                                                                        "/
\" Other things:                                                          "/
\"   - Ensure the refer(1) database named "references" is present in the  "/
\"     same directory as this.                                            "/
\""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""/
.
\" Configuration for refer(1)
.R1
accumulate
bracket-label " (" ")" ", "
join-authors ", and " ", " ", and "
move-punctuation
database references
.R2
\" Font settings (and conditional line-length for TTY output)
.nr PS 12p
.if n .nr LL 78n
.
.
.
\" Beginning of document
.TL
HTTP PGP Authentication
.AU
Patrick Grasso
.AU
Mark Wilson
.AU
Jonah Mania
.AI
Stevens Institute of Technology
.AB
.nh
We will provide a proof-of-concept for PGP key-based authentication via HTTP
as an extension to [\fURFC 7235\fP]. While this is not the first attempt to
create a key-based client authentication protocol, it lends from the benefits
of PGP and the Web of Trust. PGP public-key infrastructure already exists for
public key sharing and key certification and has been thoroughly
peer-reviewed. We present a way to build atop this infrastructure, providing
authentication on the web without the need for a password for each site the
user authenticates with.
.AE
.
.NH
Problem Statement
.PP
.nh
HTTP was initially developed without much concern for security, as the early
web consisted mainly of static, public documents. As stateful HTTP
[\fURFC 6265\fP] and user-oriented services began to appear, the need for
authentication and security became more imperative. Today, there exists a
mechanism for authentication in the HTTP 1.1 protocol [\fURFC 7235\fP], which
can be extended with new methods of authentication. The \"Basic\" method for
authentication is not frequently used, but websites will implement their own
version of the same thing. This method entails password authentication, which
is heavily relied upon but often does not provide sufficient security.
.[
Hypertext Transfer Protocol (HTTP/1.1): Authentication
.]
.PP
.nh
.
.NH
Importance of the Problem
.PP
.nh
Password authentication has, for many years, been shunned for a few reasons.
One of these is that the security factor is dependent on the user's ability to
create a hard-to-guess password, which many users do not do. As a result, if
the database containing the hashed passwords and their respective salts is
leaked, it can sometimes be fairly trivial to recover the original passwords.
\" \m[red]( \f(BIinsert reference for password crack rates\fP )\m[].
Users will often re-use the same password for multiple services, which is
problematic if one of these services has a security breach and users' passwords
are able to be recovered by the attacker. Moreover, good passwords are
difficult to remember and frequently forgotten by users. To solve this, some
services provide the ability to reset one's password by sending an email to the
address associated with one's account. This places trust in the mail services
that users use to receive e-mail, trust which may be misplaced.
\" \m[red]( \f(BIinsert reference for how SMTP is not secure\fP )\m[].
.PP
.nh
The reason for password authentication's popularity is its flexibility and
usability. It does not require techinical knowledge and does not depend on the
same machine being used to access the site. While password authentication
relies only on what the user \fBknows\fP (as opposed to what she \fBhas\fP, as
is the case for public-key authentication), PGP has many benefits which
outweigh the cost of carrying around a private key.
.
.NH
Previous Approaches
.PP
.nh
HOBA (HTTP Origin-Bound Authentication) [\fURFC 7486\fP] uses signature-based
authentication with a key pair attached to the user's agent (browser). This
method follows the spirit of our approach, but lacks the benefits of PGP's
public key infrastructure and Web of Trust. Users' information associated with
keys published in public key servers (e.g. pgp.mit.edu) can be used to supply
account information for services utilizing our proposed authentication method.
.[
HTTP Origin-Bound Authentication (HOBA)
.]
.PP
.nh
OBCs (Origin-Bound Certificates) were proposed as a solution to client
authentication by modifying TLS so that the server would check certificates
held by the client in addition to verifying the server's x509 certificate. This
solution operates below the application level, which perhaps targets a use case
for client authentication different from that which we are trying to address.
.[
Origin-Bound Certificates
.]
.
.NH
Proposal Description
.PP
.nh
We proprose to implement the HTTP Authentication type \"PGP\" on a web server
and in a web client. The server will offer the WWW-Authenticate header upon
access to restricted resources. Instead of \"Basic\", \"Digest\", or \"HOBA\",
the header will contain \"PGP\" for the <type>, as well as \"nonce\" and other
relevant <options>. The client, upon seeing this, will ask the user for
confirmation before signing the nonce and returning it to the server. From
this, the server should be able to query PGP services for information about the
key used to sign the nonce and use that to populate account information (e.g.
email address, which is typically used as a user ID).
.
.NH
Project Evaluation
.PP
.nh
We will implement a prototype to demonstrate the potential capabilities for
such a protocol. The server should be able to verify the signature that a
client has provided via HTTP. The client agent should be able to identify the
HTTP WWW-Authenticate header with PGP as the authentication type and query the
user to determine whether or not to continue the login flow. If the user
chooses to proceed, the agent will sign the nonce provided by the server and
return it in another HTTP request.
.
.
\" Bibliography/references
.[
$LIST$
.]
