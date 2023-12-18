pub(crate) mod authenticator;
pub(crate) mod authorizer;
pub(crate) mod client;

#[cfg(test)]
mod tests {
	use secp256k1;
	use secp256k1::Secp256k1;
	use super::*;

	#[test]
	fn simple_case_test() {
		let s_ctx = Secp256k1::new();

		let s = secp256k1::SecretKey::from_slice(&[0xcd; 32])
		.expect("curve order or something");
		let capital_s = s.public_key(&s_ctx);

		let (my_ctx, req) = client::request_authorization_step1(
			&s_ctx,
			&[1; 64]
		);

		let resp = authorizer::authorize(
			&s_ctx,
			&s,
			req,
			[2; 32]
		);

		let token = client::request_authorization_step2(
			&s_ctx,
			my_ctx,
			&capital_s,
			resp
		).expect("DLEQ validation should succeed");

		let challenge: [u8;0] = [0;0];

		let cred = client::show_authentication_credential(
			&challenge,
			token
		);

		let accept = authenticator::authenticate(
			&s_ctx,
			&s,
			&challenge,
			cred
		);

		assert!(accept);
	}
}
