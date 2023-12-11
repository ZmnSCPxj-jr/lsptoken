use secp256k1;
use secp256k1::Secp256k1;
use secp256k1::Verification;
use super::super::super::basics;
use super::super::types;

/** Perform the authorization.
 *
 * Gets the authorization request from the client, returns
 * the authorization response.
 *
 * Caller is responsible for first checking that the client
 * SHOULD in fact get authorized.
 *
 * This algorithm requires the private key to the service.
 * This means that the caller needs access to this private
 * key.
 *
 * The `random` parameter must be filled with high-quality
 * entropy.
 * 256 bits of entropy is best.
 * Anything higher than 128 bits of entropy is good enough
 * in practice but the caller needs to stretch that entropy
 * to the required number of bytes.
 * The strong recommendation is to either fill this in from
 * `getentropy` or `/dev/random` or equivalent in your OS,
 * or if you need a lot of randomness then use a CSPRNG that
 * you periodically re-stock from `getentropy` /
 * `/dev/random` / equivalent.
 */
pub(crate)
fn authorize<C>( s_ctx: &Secp256k1<C>,
		 private_service_key: &secp256k1::SecretKey,
		 req: types::AuthorizationRequest,
		 random: [u8; 32]
	       ) -> types::AuthorizationResponse
	where C: Verification
{
	let s = basics::sk_to_scalar(
		private_service_key.clone()
	);
	/* By construction, s != 0, as the SecretKey
	type disallows 0 from being constructed.
	*/

	let capital_s = basics::capital_g().mul_tweak(s_ctx, &s)
	.expect("impossible: SecretKey cannot be 0 thus s cannot be 0");

	/* Parse the authorization request.  */
	let types::AuthorizationRequest{blinded_point} = req;

	let capital_c = blinded_point.clone().mul_tweak(s_ctx, &s)
	.expect("impossible; SecretKey cannot be 0 thus s cannot be 0");

	/* Select k.  */
	let k = secp256k1::Scalar::from_be_bytes(random)
	.expect("probability of failure is 1 in ~2^256");
	assert!(!basics::is_scalar_0(&k));

	let e = basics::calculate_dleq_e(
		s_ctx,
		&k,
		blinded_point,
		capital_c.clone(),
		capital_s
	);

	let signed_e = basics::sk_to_scalar(
		/* e is a hash and is highly unlikely to be 0.  */
		basics::scalar_to_sk(e.clone()).mul_tweak(&s)
		.expect("impossible; SecretKey cannot be 0 thus s cannot be 0")
	);

	let d = basics::calculate_dleq_d(&k, signed_e);

	let dleq = types::DleqProof{d, e};

	types::AuthorizationResponse{capital_c, dleq}
}
