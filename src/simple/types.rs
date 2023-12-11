use secp256k1;

/** This module contains various types that are intended to
be saved on-disk or sent on messages between server and client.
*/

/** A proof of discrete log equivalence (DLEQ).  */
pub(crate) struct DleqProof {
	/** The core proof scalar.  */
	pub(crate) d: secp256k1::Scalar,
	/** The Fiat-Shamir hash to make DLEQ non-interactive.  */
	pub(crate) e: secp256k1::Scalar
}

/** Sent from client to the authorization-granting server.  */
pub(crate) struct AuthorizationRequest {
	/** The blinded point `b * G + T` to be signed.  */
	pub(crate) blinded_point: secp256k1::PublicKey
}
/** Sent from authorization-granting server to client.  */
pub(crate) struct AuthorizationResponse {
	/** The signed version of the blinded point, i.e.
	 * `s * b * G + s * T`.
	 * The "signed blinded token".
	 */
	pub(crate) capital_c: secp256k1::PublicKey,
	/** The proof of discrete log equivalence that shows
	 * that the service key was indeed multiplied with
	 * the blinded point given by the client.
	 */
	pub(crate) dleq: DleqProof
}

/** Used internally by the client, to store important state
 * between the client sending AuthorizationRequest and
 * receiving AuthorizationResponse.
 *
 * This MUST NOT be sent to the authentication or authorization
 * server!
 *
 * It should be associated with a single request-for-authorization,
 * and once the server has sent AuthorizationResponse, is passed
 * to the client code to construct the actual token.
 */
pub(crate) struct AuthorizationClientContext {
	/** The scalar of the token.  */
	pub(crate) t: [u8; 32],
	/** The blinding factor used.  */
	pub(crate) b: secp256k1::Scalar
}

/** The token that is stored client-side and then used
 * in some subsequent authentication credential-showing.
 *
 * This MUST NOT be sent to the authorization server!
 * This MUST NOT be sent to the authentication server!
 */
pub(crate) struct ServiceToken {
	/** The scalar of the token, generated by the client.  */
	pub(crate) t: [u8; 32],
	/** The signed point of the token, coming from the
	 * server.  */
	pub(crate) s_times_capital_t: secp256k1::PublicKey
}

/** The proof that the client has to show the
 * authentication server that it was authorized.
 */
pub(crate) struct AuthenticationCredential {
	/** The scalar of the token.  */
	pub(crate) t: [u8; 32],
	/** The HMAC, using `sha256(s * T)`, of the challenge.  */
	pub(crate) hmac: [u8; 32],
}

/** Used internally by the authenticator, if the secret
 * key is stored elsewhere from the machine or process
 * that accepts the client `authenticationCredential`.,
 * to store information needed across the call to the
 * process or machine that holds the secret key.
 */
pub(crate) struct AuthenticatorContext {
	/** The HMAC from the client credential.  */
	pub(crate) hmac: [u8; 32]
}
