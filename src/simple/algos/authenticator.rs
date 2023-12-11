use hashes::sha2::sha256;
use secp256k1;
use secp256k1::Secp256k1;
use secp256k1::Verification;
use super::super::super::basics;
use super::super::types;

/** Perform the authentication in a single call.
 *
 * This call requires the secret key of the authorizer!
 * Unfortunately yes, validation of a token cannot be done
 * publicly, it needs private coordination between the
 * authorizer and the authenticator.
 *
 * Return true if the credential is authentic to the given
 * challenge, false otherwise.
 *
 * The challenge should either be interactive (i.e. the
 * authenticator generates the challenge with high entropy
 * and sends to client, then client sends the
 * `types::AuthenticationCredential` object) or by using
 * Fiat-Shamir transform to remove the extra challenge
 * stage, by having the client commit to the parameters of
 * the request it wants to have authorized (e.g. the client
 * hashes the parameters of the request and uses the hash
 * as the challenge, or the client can pick one-time-use
 * numbers as the challenge and the server restricts the
 * one-time-use numbers to ensure they are one-time-use.)
 *
 * If you need to store the secret in a separate process
 * or machine, see the `authenticate_step1` and
 * `authenticate_step2` functions.
 */
pub(crate)
fn authenticate<C>( s_ctx: &Secp256k1<C>,
		    private_service_key: &secp256k1::SecretKey,
		    challenge: &[u8],
		    credential: types::AuthenticationCredential
		  ) -> bool
	where C: Verification
{
	let s = basics::sk_to_scalar(
		private_service_key.clone()
	);
	/* By construction, s != 0, as the SecretKey
	type disallows 0 from being constructed.
	*/

	let (my_ctx, capital_t) = authenticate_step1(credential);

	let s_times_capital_t = capital_t.mul_tweak(s_ctx, &s)
	.expect("impossible, by construction SecretKey cannot be 0");

	authenticate_step2(my_ctx, challenge, s_times_capital_t)
}

/** Perform the first step of authentication.
 *
 * Use this function if you need to separate the entity that
 * knows the secret key of the authorizer from
 * the authenticator.
 *
 * In that acse, this function should be called, and its
 * second result (a point / `secp256k1::PublicKey`) should be
 * sent to the trusted entity that knows the secret key.
 * That entity then multiplies the point by the secret key
 * and returns the result, which is then passed to the
 * `authenticate_step2` function.
 */
pub(crate)
fn authenticate_step1( credential: types::AuthenticationCredential
		     ) -> ( types::AuthenticatorContext,
			    secp256k1::PublicKey
			  )
{
	/* Extract credential fields.  */
	let types::AuthenticationCredential{t, hmac} = credential;

	/* Determine T.  */
	let capital_t = basics::hash_to_a_point(&t);

	/* Build context and return T.  */
	let my_ctx = types::AuthenticatorContext{hmac};
	(my_ctx, capital_t)
}

/** Perform the second step of authentication, and returns
 * true if authentic, false otherwise.
 *
 * Use this function if you need to separate the entity that
 * knows the secret key of the authorizer from
 * the authenticator.
 * 
 * In that case, call the function `authenticate_step1` on
 * the client credential first, then send the given point
 * returned by that function to the trusted entity that
 * knows the secret key.
 * That entity then multipliues the point by the secret key
 * and returns the resulting point to the authenticator,
 * to be passed to this function.
 */
pub(crate)
fn authenticate_step2( my_ctx: types::AuthenticatorContext,
		       challenge: &[u8],
		       s_times_capital_t: secp256k1::PublicKey
		     ) -> bool
{
	/* Extract context fields.  */
	let types::AuthenticatorContext{hmac} = my_ctx;

	/* Get the serialization of s * T.  */
	let serial_s_times_capital_t = s_times_capital_t.serialize();
	/* hash it.  */
	let h = sha256::hash(&serial_s_times_capital_t).into_bytes();

	/* Get the hmac'.  */
	let hmac_prime = basics::hmac_sha256(&h, challenge);

	hmac == hmac_prime
}
