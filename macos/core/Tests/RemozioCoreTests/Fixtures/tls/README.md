# Public TLS fixtures

These are synthetic OpenSSL certificates. All private keys were generated in a temporary directory and deleted. No operational identity is included.

- `peer.spki`: DER SubjectPublicKeyInfo for the P-256 test key.
- `peer.der` and `renewed.der`: different self-signed certificates with that key, serials 1 and 2, and different synthetic subjects.
- `wrong.der`: a certificate with another P-256 key.
- `rsa.der`: a certificate with an RSA 2048-bit key.

Certificates have two-day validity intervals. Tests derive explicit dates from each certificate, so they do not depend on the current date. OpenSSL `ecparam -name prime256v1 -genkey`, `pkey -pubout -outform DER`, and `req -new -x509 -days 2 -outform DER` generated the P-256 fixtures. The RSA fixture used `req -newkey rsa:2048`.
