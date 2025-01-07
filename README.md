# LSP Token Library
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZmnSCPxj-jr%2Flsptoken.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FZmnSCPxj-jr%2Flsptoken?ref=badge_shield)


## Motivation

An LSP might want to provide additional Lightning- or
Bitcoin-related services beyond merely providing liquidity and
access to the Lightning Network.
For example, clients may need to access some SPV server in order
to reduce bandwidth load at the client.

However, there is an obvious economic reason for the LSP to
restrict the provision of such services to clients it has economic
ties with (i.e. a channel or a promise of a channel, such as a
pending LSPS1 or LSPS2 channel request).
The simplest implementation is to demand that a purported client
sign, using its node ID, some string, before the LSP provides such
an additional service.

This simplest implementation has the flaw that the LSP is now
aware of exactly which node the client controls.
This may allow the LSP to deny a vital service, such as block
information, to support an attack on the specific node ID.
Although no LSP is expected to attack its clients, external
hackers may gain access to the LSP hardware and cause such attacks
to occur.
Reducing the information that an LSP has about its clients makes
it less attractive as a hacking target, thus protecting the
clients.

This LSPS describes a standard for how an LSP may provide service
tokens, gratis or for a fee, to clients, and how clients can use
the service tokens to gain access to additional services.

This LSPS unlinks two security concepts:

* Authorization: giving permission to some entity to use a
  service.
* Authentication: validating that an entity has permission to
  use a service.

Service tokens generated during authorization are blinded by the
client.
The client can then unblind the token during the subsequent
authentication.
This blinding step prevents the server from linking a token
provided during authorization from when the client uses the token
during authentication.

### Actors

The 'LSP' is the entire entity that provides both access to the
Lightning Network, and additional services.
The 'client' is the entity to which the LSP provides such access
and additional services.

The 'LSP-node' is the part of the LSP entity that is a Lightning
Network node, which the client has a channel (or promise of a
channel) with, and which provides the client access to the
Lightning Network.
It also serves as the authorizer.

The 'LSP-server' is the part of the LSP entity that provides
one or more of the additional services provided by the LSP.
It includes an authenticator of the authorization provided by the
LSP-node.

## Cryptographic Scheme For `simple` Module

For the `simple` module of this library, please note the following
limitations:

* It is intended to be used for single-use individual "tickets"
  for a service.
* It is NOT appropriate for metered services where various operations
  may have different token costs, e.g. a data storage service might want
  to charge more tokens for storing a novel piece of data compared to
  replacing a piece of data or retrieving it.

The blinded service token scheme is based on [PrivacyPass][], with
the following differences:

* The curve is SECP256K1.
  (**Rationale** This is the standard curve used in Bitcoin, and
  unlike the NIST P-256 / SECP256R1 curve, its parameters are
  stringently derived to achieve Koblitz curve properties; in
  theory, NIST could have chosen the supposedly-random parameters
  of NIST P-256 /  SECP256R1 to have some subtle flaw.)
* The hash function is SHA-256 from the SHA-2 family.
  (**Rationale** The SHA-2 family is considered secure even with
  the advent of the SHA-3 family, which is considered an
  alternative and not a replacement to SHA-2, and SHA-256 from the
  SHA-2 family is widely used in Bitcoin.)
* Hash-to-a-point is done by SHA-256 of the input, then treating
  the resulting hash as the X coordinate of a point on the
  SECP256K1 curve with an even Y coordinate; if the X coordinate
  is not on the curve, then hash the hash again ad infinitum,
  until we get a hash where, if it is the X coordinate of a point,
  lies on the curve.
  (**Rationale** The standard `bitcoin-core/secp256k1` project
  includes a function to read in a point in "compressed form",
  where the X coordinate is given and only the sign of the Y
  coordinate is encoded; by prepending `02` to the result of the
  hash, the result can be fed directly into this function to
  check if it encodes a point on the curve.
  While this becomes a variable-time algorithm, the input to the
  hash-to-a-point operation is completely public information and
  the timing does not leak any private data.)
* The blinding is done additively instead of multiplicatively.
  (**Rationale** The standard `bitcoin-core/secp256k1` project
  exposes APIs to perform additive inverse / negation of both
  scalars and field elements / points, but does not expose any API
  to perform multiplicative inverse / division by scalar, which
  would be needed to unblind the tokens.)
* The discrete log equality ("DLEQ") proof is based on
  [this sketch](https://asecuritysite.com/encryption/logeq).
* The CSPRNG used in batched DLEQ is ChaCha20.

[PrivacyPass]: https://privacypass.github.io/protocol/

### Authorization Protocol

First, the client and the LSP-node establishes the service public
key.
This is some public key (a point on SECP256K1) that the LSP-node
"signs" tokens for, and which the LSP-server will later accept as a
service tokem if signed using that public key.
The client, in particular, needs to ensure that the LSP uses the
same service public key for all clients, and does not use a
special key for each client.

The LSP-node publishes the point `S` (the service public key), and
knows the private key `s` such that `S = s * G`, where `G` is the
standard generator point for SECP256K1.

```
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = SEC-decode('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
```

When requesting authorization, the client generates a random
256-bit (32 bytes) number, `t`, the token.

The client then performs hash-to-a-point on `t`:

* Set `input = t`.
* In a loop:
  * Set `x` to `SHA-256(input)`.
  * If `x`, when used as an X coordinate, is a point on the
    SECP256K1 curve (`y * y = x * x * x + 7`), then exit this
    loop and return the point where the Y coordinate is even and
    the X coordinate is `x`.
    * (**Non-normative**) When using `bitcoin-core/secp256k1`,
      you can prepend a `02` byte to the hash, then pass the
      33-byte buffer to `secp256k1_ec_pubkey_parse`; if it returns
      non-0, then the resulting point lies on the SECP256K1 curve
      and has an even Y coordinate.
  * Otherwise, set `input = x` and continue the loop.

Call the result of the above operation `T`.

The client then generates a second random 256-bit number, `b`,
the blinding factor.
It then adds `b * G` to the above point `T`.

The client then sends `b * G + T` to the server.

The LSP-node then multiplies the given point by its secret key `s`
and returns `s * (b * G + T)`, called `C` or the blinded token
signature.

The LSP-node also provides a proof of discrete log equality,
proving that for `s * G` (`S`) and `s * (b * G + T)` (`C`), the
`s` is the same.

The proof of discrete log equality is generated this way:

* Generate random 256-bit number `k`.
* Compute `A` as `k * G`.
* Compute `B` as `k * (b * G + T)`.
* Compute `e` as the SHA-256 hash of the concatenation of the
  following:
  * The 33-byte SEC encoding of `A`.
  * The 33-byte SEC encoding of `B`.
  * The 33-byte SEC encoding of `S` (the server public key).
  * The 33-byte SEC encoding of `C` (the blinded token signature).
* Compute `d` as `k + e * s`, where `s` is the server private key.

The LSP-node then sends `C` (the blinded token signature) and
`(e, d)` (the proof of discrete log equality) to the client.

The client then first validates that the proof of discrete log
equality is valid.

* Compute `A'` as `d * G - e * S`.
* Compute `B'` as `d * (b * G + T) - e * C`.
* Compute `e'` as the SHA-256 hash of the concatenation of the
  following:
  * The 33-byte SEC encoding of `A'`.
  * The 33-byte SEC encoding of `B'`.
  * The 33-byte SEC encoding of `S`.
  * The 33-byte SEC encoding of `C`.
* If `e'` equals `e`, then validation succeeds, otherwise,
  validation fails.

Then, once the validation succeeds, the client can unblind `C`,
by calculating `C - b * S`.
This results in `s * T`.

The client then stores `(t, s * T)` as the token.

#### Batched Authorization

A single client may request for multiple tokens in a single
authorization request.

In that case, the client generates multiple `t[i]` and multiple
`b[i]`, and hashes each `t[i]` onto a point `T[i]`, where `i`
is a numeric 0-based index, with `n` tokens to be generated
(such that `0 <= i <= n - 1`).
The client then sends `(b[i] * G + T[i])` to the LSP-node for
authorization.

The LSP-node, once it has decided to authorize the client and
issue the specified number of tokens, then generates `C[i]`
for each point, by calculating `s * (b[i] * G + T[i])` for all
`i`.

The LSP-node, in this context, provides a batched proof of
discrete log equivalance.
This is a single succinct proof that all the returned points
`C[i]` were computed by multiplying the server private key `s` to
the corresponding `(b[i] * G + T[i])`.

To do so, the LSP-node computes an aggregate `C[all]`, by
the following process:

* Compute `z` as the SHA-256 hash of the concatenation of each
  `C[i]`, in the order of the index `i`.
* Compute `q[i]`:
  * Start with a plain text containing `n * 32` bytes of value
    `0x00`, where `n` is the number of tokens to issue.
  * Encrypt the plain text with ChaCha20 stream cipher, with the
    `z` as the symmetric key, and the nonce as all `0x00` bytes.
  * Get `q[i]` as the resulting ciphertext at indices `i * 32`
    to `(i * 32) + 31`, interpreted as a 256-bit big-endian
    number.
* Compute `C[all]` as the sum of `q[i] * C[i]` for all `i`.
* Compute the sum of `q[i] * (b[i] * G + T[i])` for all `i`.

The LSP-node then constructs the basic proof of discrete log
equivalance using `C[all]` and the sum of
`q[i] * (b[i] * G + T[i])` for all `i`, using those values to
compute the `e` and `B` in the proof.

* Compute `B` as `k * (sum of (q[i] * (b[i] * G + T)))`.
* Replace the `C` in the hash operation of `e` with `C[all]`.

Similarly, on validation, the client computes `C[all]` and the
sum of `q[i] * (b[i] * G + T[i])` for all `i`, using those
values to compute `e'` and `B'` in the validation.

* Compute `B'` as `d * (sum of (q[i] * (b[i] * G + T))) - e * C[all]`.
* Replace the `C` in the hash operation of `e` with `C[all]`.

### Authentication Protocol

The LSP-server issues a challenge string, `m`, to the client.
The challenge string SHOULD be a one-time-use string that is
issued each time the LSP-server wants to authenticate some
client or some use of the service.
A Fiat-Shamir transform can also be used to generate the
challenge string from the hash of some data in the request.

> **Rationale** A one-time-use challenge string prevents an
> token hijacking attack.
> If a third party is able to see the unencrypted communication
> between client and LSP-server, and the challenge string is a
> fixed constant or otherwise changes rarely, then the third
> party can also use the token by simply copying the data sent
> by the client.
>
> In contexts where the client and LSP-server already use an
> encrypted communication (where the encryption keys are
> rotated every time the authentication is made) then it is
> acceptable for the challenge string to be a known constant
> shared by the client and LSP-server.
> This can remove an additional request-response cycle in
> the protocol.
>
> For cases where the client uses a token for a single
> request-response RPC-type interaction with the LSP-server, and
> where the request parameters include cryptographic randomness
> that the client has an incentive to change for each request, it
> is possible to generate the challenge string via the hash of the
> parameters to the request, i.e. use a Fiat-Shamir transform to
> generate the challenge string.
> For example, if a token is used to request the storage of a
> single encrypted blob of data, the hash of the blob can be used
> as part of the challenge string, and only a single message from
> the client to the LSP-server is needed.

The client then selects a token `(t, s * T)` to use for
authentication.
It then computes the HMAC of the challenge string `m`, using
`s * T` as the key:

* Compute `h` as the SHA-256 of the 33-byte compressed SEC
  encoding of `s * T`.
* Calculate HMAC-SHA-256 using `h` as the private key and
  `m` as the message:
  * Calculate the SHA-256 of the concatenation of:
    * 32 bytes of `0x5C` XORed with the 32 bytes of `h`.
    * 32 bytes of `0x5C`.
    * The 32 bytes SHA-256 of the concatenation of:
      * 32 bytes of `0x36` XORed with the 32 bytes of `h`.
      * 32 bytes of `0x36`.
      * The message `m`.

The client then sends `(t, HMAC(s * T, m))` (and possibly `m` as
well as any additional information needed for the server to
validate `m`, if the transport is stateless) to the LSP-server.

The LSP-server then validates the token:

* Compute `s * T`:
  * Calculate `T` by hash-to-a-point of `t`, described above.
  * Multiply `T` by the private key `s` to get `s * T`.
* Calculate `h'` as the SHA-256 of the 33-byte compressed SEC
  encoding of `s * T`.
* Calculate HMAC-SHA-256 using `h'` as the private key and
  `m` as the message, described above.
* If the HMAC-SHA-256 result is the same as the value sent by
  the client, the token is valid and the client is authorized.

The LSP-server MUST add `t` to a set or map of already-used
tokens.
Depending on the use-case, the LSP-server SHOULD reject
already-used `t`s.

### LSP Key Rotation

The key `S` used in both LSP-node authorization and LSP-server
authentication MUST NOT be the LSP-node node ID.

The key `S` MAY be rotated by the LSP periodically.
The LSP MUST NOT rotate `S` faster than once every 7 days.

The LSP-server MUST accept tokens signed by the most recent `S`
key, and MAY accept tokens signed by some number of the most
recent `S` keys.

> **Rationale** The tokens described here cannot contain any
> information other than "this client was authorized".
> In particular, it cannot contain additional information such
> as expiry.
> The only way to implement token expiration is to rotate the
> server key `S` periodically and to accept tokens that were
> signed using a sufficiently-recent key `S`.
>
> Without token expiration, a patient attacker may collect
> tokens over several years, including acquiring tokens from
> hacked or neglected clients (such as by diving into disposed
> storage devices), and then use a large number of tokens to
> overload the LSP-server.
>
> Tokens signed with a particular `S` are linked to that `S`.
> Thus, if the LSP rotate keys too often, it would be able to
> determine if a client acquired the tokens at a particular
> time frame.
> By restricting how often the LSP can rotate keys, such linking
> is reduced.

* The LSP-node signs with a specific server key, the "current
  service key".
  * The LSP-node restricts the number of tokens it issues to
    clients for the current service key.
    Once the LSP-node rotates the current service key to a new
    one, it resets the number of tokens it has issued to a
    client.
  * The LSP publishes this key in a location accessible to all, so
    that clients can ensure that the service key is not unique to
    them (which would let the LSP link the tokens to specific
    clients).
* The LSP-server accepts tokens of the current service key, or
  the past N most recent service keys, with N selected by the LSP.
  * The LSP-node communicates to the client a datetime at which
    the LSP-server will stop accepting authorized service tokens
    for the current authorization.
  * When the LSP-server stops accepting an authorized service
    token for a particular previous service key, the LSP-server
    MAY delete the `t`s recorded for that key, as the entire
    set of tokens for that key will already be invalid.

## Using The Library

As of this version, the library has sub-module `simple::types`
which includes the messages to be sent between client and the
authorization and authentication servers.
The innards of the structures are exposed so that you can
destruct and construct them yourself freely, and to serialize
and desrialize them in whatever format you fancy.
This is not (yet) a batteries-included library.

There is a sub-module `simple::algos` which includes
sub-modules `client`, `authorizer`, and `authenticator`, which
contain actual code for generating the messages and processing
them, as well as generating the service token to be saved on
the client side.

(TODO) very much a work in progress


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FZmnSCPxj-jr%2Flsptoken.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FZmnSCPxj-jr%2Flsptoken?ref=badge_large)