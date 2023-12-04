use hashes::sha2::sha256;
use secp256k1::PublicKey;
use secp256k1::Scalar;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use secp256k1::Verification;
use super::super::super::basics;
use super::super::types;

fn get_blinded_token<C>( s_ctx: &Secp256k1<C>,
			 t: &[u8; 32],
			 b: &secp256k1::Scalar
		       ) -> secp256k1::PublicKey
	where C: Verification
{
	let capital_t = basics::hash_to_a_point(t);
	capital_t.add_exp_tweak(s_ctx, b)
	.expect("~impossible, requires T == -b * G")
	/*
	The underlying libsecp256k1 function,
	secp256k1_ec_pubkey_tweak_add, fails if the scalar is
	out-of-range (but the Rust `Scalar` type cannot be
	constructed unless the scalar IS in range) or if the
	resulting addition equals the point at infinity (i.e.
	`0 * G`).
	The former is impossible by construction due to the
	use of the `Scalar` type.
	The latter is only possible if `T` == `-b * G`, which
	is very unlikely and the probability is basically 1
	in the prime order of SECP256K1; handling this case
	is unnecessary as the probability is ridiculously
	low.
	*/
}

/** Generate an authorization request given some
 * random bytes.
 *
 * NOTE: The caller is responsible for acquiring
 * cryptographic-quality entropy!
 * Please get this from `/dev/urandom` or `getentropy`
 * or similar mechanisms to get high-quality entropy,
 * such as by seeding from such and using a CSPRNG to
 * stretch the randomness acquired.
 *
 * 256 bits of randomness should be more than sufficient
 * (160 bits would probably still be good, and 128 bits is
 * still acceptable in practice), however it is the caller
 * responsibility to stretch its acquired entropy to the
 * 512 bits this requires (such as by CSPRNG).
 */
pub(crate)
fn request_authorization_step1<C>( s_ctx: &Secp256k1<C>,
				   random: &[u8; 64]
				 )
		-> ( types::AuthorizationClientContext,
		     types::AuthorizationRequest
		   )
	where C: Verification
{
	/* Cut up the randomness.  */
	let mut t: [u8; 32] = [0; 32];
	t.copy_from_slice(&random[0..32]);
	let mut b_rand: [u8; 32] = [0; 32];
	b_rand.copy_from_slice(&random[32..64]);
	/* Generate scalar b from the randomness for b.  */
	let b = basics::randomness_to_a_scalar(&b_rand);

	/* If the caller did get high-quality randomness
	 * then the probability of b being 0 would be
	 * 1 in 2^256.
	 * So this checks if the caller did not get
	 * high-quality randomness.
	 */
	assert!(!basics::is_scalar_0(&b));

	/* Generate point b * G + T */
	let blinded_token = get_blinded_token(s_ctx, &t, &b);

	/* Generate context, moving ownership of t and b.  */
	let my_ctx = types::AuthorizationClientContext {
		t, b
	};

	/* Generate the outgoing request, moving ownership of the
	 * blinded point.
	 */
	let req = types::AuthorizationRequest {
		blinded_point: blinded_token
	};

	(my_ctx, req)
}

/** Generate the token, given the response from
 * the authorization server.
 *
 * If this fails, validation of the DLEQ failed.
 */
pub(crate)
fn request_authorization_step2<C>(s_ctx: &Secp256k1<C>,
				  my_ctx: types::AuthorizationClientContext,
				  service_key: &secp256k1::PublicKey,
				  resp: types::AuthorizationResponse
				 ) -> Result<types::ServiceToken, ()>
	where C: Verification
{
	/* Extract our context variables.  */
	let types::AuthorizationClientContext{t, b} = my_ctx;

	/* Extract our response varables.  */
	let types::AuthorizationResponse{capital_c, dleq} = resp;
	let types::DleqProof{d, e} = dleq;

	/* Check DLEQ proof.  */
	let blinded_token = get_blinded_token(s_ctx, &t, &b);
	if !basics::validate_dleq(s_ctx, blinded_token, capital_c, service_key.clone(), d, e) {
		return Err(());
	}

	/* Unblind.  */
	/* negate() only exists on SecretKey, but we need Scalar
	 * to unblind.
	 *
	 * scalar_to_sk can crash if b == 0, but we checked against
	 * that in request_authorization_step1
	 */
	let neg_b = basics::sk_to_scalar(
		basics::scalar_to_sk(b).negate()
	);
	let capital_s = service_key.clone();
	let neg_b_times_capital_s = capital_s.mul_tweak(s_ctx, &neg_b)
	.expect("impossible, only fails if b is 0");
	/*    s * T = C - b * S
	 * => s * T = s * (b * G + T) - b * S
	 * => s * T = s * b * G + s * T - b * s * G
	 * => s * T = s * T ; QED
	 */
	let s_times_capital_t = capital_c.combine( /* combine == add point.  */
		&neg_b_times_capital_s
	).expect("impossible, fail only if T == -b * G, which is negligible probability");

	Ok(types::ServiceToken{t, s_times_capital_t})
}

/** Generate a show-credential message for the
 * authenticator server.
 *
 * `challenge` is an arbitrary string (of bytes, not
 * human-readable characters) that "binds" this showing
 * of the token.
 * It exists to prevent token-hijacking attacks.
 *
 * Ideally, the challenge should be a string from the
 * authenticator server, generated from crypto-grade
 * entropy.
 *
 * Alternatively, if the credential is shown in context
 * with some kind of API call and some pseudonym of the
 * API-caller, you can use Fiat-Shamir transform, which
 * is just cryptographer-fancy-schmancy talk for "hash
 * all the parameters and use the hash instead of a
 * challenge from the verifier".
 * This effectively commits the credential showing to
 * the specific API parameters, and if the "parameters"
 * includes "who called the API" then hijacking the
 * token is pointless since it would perform the exact
 * same call anyway.
 *
 * Finally, if token hijacking is not an issue with
 * your client-server communications, you can set
 * `challenge` to a constant string, though this is
 * not recommended and is at the edge of rolling your
 * own crypto.
 */
pub(crate)
fn show_authentication_credential<C>( s_ctx: Secp256k1<C>,
				      challenge: &[u8],
				      token: types::ServiceToken
				    ) -> types::AuthenticationCredential
	where C: Verification
{
	let types::ServiceToken{t, s_times_capital_t} = token;

	/* Get the encoding of s * T.  */
	let serial_s_times_capital_t = s_times_capital_t.serialize();
	/* Hash it.  */
	let h = sha256::hash(&serial_s_times_capital_t).into_bytes();

	/* Get the hmac.  */
	let hmac = basics::hmac_sha256(&h, challenge);

	types::AuthenticationCredential{t, hmac}
}
