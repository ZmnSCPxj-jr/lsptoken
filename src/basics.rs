use hashes::sha2::sha256;
use secp256k1;
use secp256k1::PublicKey;
use secp256k1::Scalar;

pub type Point = secp256k1::PublicKey;

/* Basic operations.  */

pub fn hash_to_a_point(message: &[u8]) -> Point {
	let mut x = sha256::hash(message);
	loop {
		let mut buf: [u8; 33] = [0; 33];
		buf[0] = 0x02;
		buf[1..33].clone_from_slice(&x.into_bytes());
		match Point::from_slice(&buf) {
			Ok(p) => return p,
			Err(_) => {
				x = sha256::hash(&buf[1..33]);
				continue;
			}
		}
	}
}

pub fn randomness_to_a_scalar(randomness: &[u8; 32]) -> secp256k1::Scalar {
	let mut buf: [u8; 32] = randomness.clone();
	loop {
		match Scalar::from_be_bytes(buf.clone()) {
			Ok(s) => return s,
			Err(_) => {
				let x = sha256::hash(&buf);
				buf.clone_from_slice(&x.into_bytes());
				continue;
			}
		}
	}
}

/* secp256k1::Scalar and secp256k1::SecretKey are the same; they
 * even have the same validity requirements, and can be converted
 * to each other trivially.
 * If there were unsafe conversions between them that would be
 * best but sadly the Rust wrapper around secp256k1 does not
 * expose such conversions.
 */
pub fn scalar_to_sk(s: secp256k1::Scalar) -> secp256k1::SecretKey {
	secp256k1::SecretKey::from_slice(&s.to_be_bytes())
	.expect("scalar is 0")
}
pub fn sk_to_scalar(s: secp256k1::SecretKey) -> secp256k1::Scalar {
	secp256k1::Scalar::from_be_bytes(s.secret_bytes())
	.expect("impossible, as the validity requirements of SecretKey and Scalar are the same")
}
pub fn negate_scalar(s: secp256k1::Scalar) -> secp256k1::Scalar {
	sk_to_scalar(scalar_to_sk(s).negate())
}

/* For some reason, converting from a secret key to a public
 * key (i.e. multiplying G by the secret key) requires a
 * signing context, but tweaking a public key by a scalar
 * (i.e. multiplying arbitrary point P to the secret key)
 * requires a verification context.
 *
 * For consistency we just use the verification context and
 * tweak G by multiplication instead of converting secret
 * key to public key, even though they are the same maths.
 */
pub
fn capital_g() -> secp256k1::PublicKey {
	secp256k1::PublicKey::from_slice(
	&[ 0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
	   0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
	   0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
	   0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
	   0x98
	])
	.expect("constant is known valid")
}

fn dleq_hash( a: secp256k1::PublicKey,
	      b: secp256k1::PublicKey,
	      capital_s: secp256k1::PublicKey,
	      s_times_point: secp256k1::PublicKey
	    ) -> secp256k1::Scalar {
	let mut buf: [u8; 33 * 4] = [0; 33 * 4];
	buf[  0.. 33].clone_from_slice(&a.serialize());
	buf[ 33.. 66].clone_from_slice(&b.serialize());
	buf[ 66.. 99].clone_from_slice(&capital_s.serialize());
	buf[ 99..132].clone_from_slice(&s_times_point.serialize());

	let h = sha256::hash(&buf);

	secp256k1::Scalar::from_be_bytes(h.into_bytes())
	.expect("assuming ROM holds (= SHA-2 is not second-preimage-broken), probability of failure is about 1 in ~2^256")
}

pub fn is_scalar_0(s: &secp256k1::Scalar) -> bool {
	s == &secp256k1::Scalar::from_be_bytes([0; 32]).expect("0 < curve order")
}

/* Determine if a DLEQ proof is correct.  */
pub fn validate_dleq<C>( s_ctx: &secp256k1::Secp256k1<C>,
			 point: secp256k1::PublicKey,
			 s_times_point: secp256k1::PublicKey,
			 s_times_g: secp256k1::PublicKey,
			 d: secp256k1::Scalar,
			 e: secp256k1::Scalar
		       ) -> bool
	where C: secp256k1::Verification
{
	/* scalar_to_sk fails if scalar is 0, so check it here.  */
	if is_scalar_0(&e) { return false; }

	/* A' = d * G - e * S */
	/* -e */
	let neg_e = sk_to_scalar(scalar_to_sk(e).negate());
	/* -e * S */
	let neg_e_times_capital_s = s_times_g.mul_tweak(s_ctx, &neg_e)
	.expect("only fails if e = 0, which we checked before.  ");
	/* d * G */
	let d_times_capital_g = match capital_g().mul_tweak(s_ctx, &d) {
		Ok(p) => p,
		/* Could happen if server gives d = 0.  */
		Err(_) => { return false; }
	};
	let a_prime = match d_times_capital_g.combine(&neg_e_times_capital_s) {
		Ok(p) => p,
		/* Could happen if server gives d = e * s */
		Err(_) => { return false; }
	};

	/* B' = d * point - e * s_times_point */
	/* -e * s_times_point */
	let neg_e_times_s_times_point = s_times_point.mul_tweak(s_ctx, &neg_e)
	.expect("already checked against e = 0 earlier");
	/* d * point */
	let d_times_point = point.mul_tweak(s_ctx, &d)
	.expect("already checked against d = 0 earlier");
	let b_prime = d_times_point.combine(&neg_e_times_s_times_point)
	.expect("already checked against d = e * s earlier");

	/* e' */
	let e_prime = dleq_hash(a_prime, b_prime, s_times_g, s_times_point);

	/* Core validation */
	e_prime == e
}

/* Compute `e` for the DLEQ proof.  */
pub fn calculate_dleq_e<C>( s_ctx: &secp256k1::Secp256k1<C>,
			    k: &secp256k1::Scalar,
			    point: secp256k1::PublicKey,
			    s_times_point: secp256k1::PublicKey,
			    s_times_g: secp256k1::PublicKey
			  ) -> secp256k1::Scalar
	where C: secp256k1::Verification
{
	let capital_a = capital_g().mul_tweak(s_ctx, k)
	.expect("If k is truly random, probability of k == 0 is 1 in ~2^256");

	let capital_b = point.mul_tweak(s_ctx, k)
	.expect("If k is truly random, probability of k == 0 is 1 in ~2^256");

	dleq_hash(capital_a, capital_b, s_times_g, s_times_point)
}

/* Compute `d` for the DLEQ proof, given `k` and `signed_e = e * s`.  */
pub fn calculate_dleq_d( k: &secp256k1::Scalar,
			 signed_e: secp256k1::Scalar
		       ) -> secp256k1::Scalar
{
	sk_to_scalar(
		scalar_to_sk(signed_e).add_tweak(k)
		.expect("Impossible with high probability, assuming s and k were selected at random, and e was SHA256 is in the ROM.")
	)
}

/* Compute the HMAC-SHA256 as per RFC-2104.  */
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
	const SHA256_BLOCK_SIZE: usize = 64;

	/* K' */
	let mut key_prime: [u8; SHA256_BLOCK_SIZE] = [0; SHA256_BLOCK_SIZE];
	if key.len() <= SHA256_BLOCK_SIZE {
		key_prime[..key.len()].clone_from_slice(key);
	} else {
		key_prime[..32].clone_from_slice(
			&sha256::hash(key).into_bytes()
		);
	}

	/* Calculate ipad and opad.  */
	let mut ipad: [u8; SHA256_BLOCK_SIZE] = [0x36; SHA256_BLOCK_SIZE];
	ipad
		.iter_mut()
		.zip(key_prime.iter())
		.for_each(|(x1, x2)| *x1 ^= *x2);
	let mut opad: [u8; SHA256_BLOCK_SIZE] = [0x5C; SHA256_BLOCK_SIZE];
	opad
		.iter_mut()
		.zip(key_prime.iter())
		.for_each(|(x1, x2)| *x1 ^= *x2);

	/* Prepend the `ipad` to the message.  */
	let mut imsg = ipad.to_vec();
	imsg.extend(msg);
	/* Prepend the `opad` to the hash of the above.  */
	let mut omsg = opad.to_vec();
	omsg.extend(sha256::hash(&imsg).into_bytes());

	/* Return the hash of the final message.  */
	sha256::hash(&omsg).into_bytes()
}

#[cfg(test)]
mod tests {
	use hex;
	use secp256k1::All;
	use secp256k1::Secp256k1;
	use super::*;

	fn point(h: &str) -> Point {
		let buf = hex::decode(h)
		.expect("Input to point function must be hex form of point");
		return Point::from_slice(&buf)
		.expect("Input to point function must be a valid point");
	}

	#[test]
	fn hash_to_a_point_test_vectors() {
		/* Hashed 1 time.  */
		assert_eq!(hash_to_a_point(&[]), point("02e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
		/* Hashed 1 time.  */
		assert_eq!(hash_to_a_point(&[0]), point("026e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"));
		/* Hashed 2 times.  */
		assert_eq!(hash_to_a_point(&[0, 0]), point("02407feb4a4b8303baf4f84e29a209e0dcfd62e81f88c8edb7675c5a95d90e5c90"));
	}

	fn scalar(h: &str) -> secp256k1::Scalar {
		let raw_buf = hex::decode(h)
		.expect("Input to scalar function must be hex form of scalar");
		let mut buf: [u8; 32] = [0; 32];
		buf.clone_from_slice(&raw_buf);
		return secp256k1::Scalar::from_be_bytes(buf)
		.expect("Input to scalar function must be a valid scalar")
	}

	/* Check that our capital_g() function corresponds to
	 * the SECP256K1 standard generator G.
	 */
	fn check_capital_g(h: &str) {
		let s_ctx = Secp256k1::new();
		let s = scalar(h);
		let sk = scalar_to_sk(s.clone());
		let pk = sk.public_key(&s_ctx);
		let s_times_capital_g = capital_g().mul_tweak(&s_ctx, &s)
		.expect("scalr should not be 0");
		assert_eq!(pk, s_times_capital_g);
	}

	#[test]
	fn capital_g_test_vectors() {
		check_capital_g("1111111111111111111111111111111111111111111111111111111111111111");
		check_capital_g("2222222222222222222222222222222222222222222222222222222222222222");
		check_capital_g("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
	}

	#[test]
	fn hmac_sha256_test_vectors() {
		/* wikipedia*/
		assert_eq!(
			hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog"),
			[0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
			 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
			 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
			 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8]
		);
		/* NIST HMAC test vector [L=32] Count=30 */
		assert_eq!(
			hmac_sha256(
			/*key*/
				&[0x97, 0x79, 0xd9, 0x12,
				  0x06, 0x42, 0x79, 0x7f,
				  0x17, 0x47, 0x02, 0x5d,
				  0x5b, 0x22, 0xb7, 0xac,
				  0x60, 0x7c, 0xab, 0x08,
				  0xe1, 0x75, 0x8f, 0x2f,
				  0x3a, 0x46, 0xc8, 0xbe,
				  0x1e, 0x25, 0xc5, 0x3b,
				  0x8c, 0x6a, 0x8f, 0x58,
				  0xff, 0xef, 0xa1, 0x76],
			/*msg*/
				&[0xb1, 0x68, 0x9c, 0x25,
				  0x91, 0xea, 0xf3, 0xc9,
				  0xe6, 0x60, 0x70, 0xf8,
				  0xa7, 0x79, 0x54, 0xff,
				  0xb8, 0x17, 0x49, 0xf1,
				  0xb0, 0x03, 0x46, 0xf9,
				  0xdf, 0xe0, 0xb2, 0xee,
				  0x90, 0x5d, 0xcc, 0x28,
				  0x8b, 0xaf, 0x4a, 0x92,
				  0xde, 0x3f, 0x40, 0x01,
				  0xdd, 0x9f, 0x44, 0xc4,
				  0x68, 0xc3, 0xd0, 0x7d,
				  0x6c, 0x6e, 0xe8, 0x2f,
				  0xac, 0xea, 0xfc, 0x97,
				  0xc2, 0xfc, 0x0f, 0xc0,
				  0x60, 0x17, 0x19, 0xd2,
				  0xdc, 0xd0, 0xaa, 0x2a,
				  0xec, 0x92, 0xd1, 0xb0,
				  0xae, 0x93, 0x3c, 0x65,
				  0xeb, 0x06, 0xa0, 0x3c,
				  0x9c, 0x93, 0x5c, 0x2b,
				  0xad, 0x04, 0x59, 0x81,
				  0x02, 0x41, 0x34, 0x7a,
				  0xb8, 0x7e, 0x9f, 0x11,
				  0xad, 0xb3, 0x04, 0x15,
				  0x42, 0x4c, 0x6c, 0x7f,
				  0x5f, 0x22, 0xa0, 0x03,
				  0xb8, 0xab, 0x8d, 0xe5,
				  0x4f, 0x6d, 0xed, 0x0e,
				  0x3a, 0xb9, 0x24, 0x5f,
				  0xa7, 0x95, 0x68, 0x45,
				  0x1d, 0xfa, 0x25, 0x8e]
			),
			/*tag*/
			[0x76, 0x9f, 0x00, 0xd3,
			 0xe6, 0xa6, 0xcc, 0x1f,
			 0xb4, 0x26, 0xa1, 0x4a,
			 0x4f, 0x76, 0xc6, 0x46,
			 0x2e, 0x61, 0x49, 0x72,
			 0x6e, 0x0d, 0xee, 0x0e,
			 0xc0, 0xcf, 0x97, 0xa1,
			 0x66, 0x05, 0xac, 0x8b]
		);
	}

	fn test_dleq_correctness( k: &str,
				  s: &str,
				  p: &str
				) {
		let k = scalar(k);
		let s = scalar(s);
		let p = point(p);

		let s_ctx = Secp256k1::new();

		let s_times_p = p.clone().mul_tweak(&s_ctx, &s)
		.expect("s must not be 0.");
		let s_times_g = capital_g().mul_tweak(&s_ctx, &s)
		.expect("s must not be 0.");

		let e = calculate_dleq_e(
			&s_ctx,
			&k,
			p.clone(),
			s_times_p.clone(),
			s_times_g.clone()
		);
		let signed_e = sk_to_scalar(
			scalar_to_sk(e).mul_tweak(&s)
			.expect("s != 0")
		);
		let d = calculate_dleq_d(&k, signed_e);

		let validate = validate_dleq(
			&s_ctx,
			p,
			s_times_p,
			s_times_g,
			d,
			e
		);

		assert!(validate);
	}

	#[test]
	fn dleq_test_vectors() {
		test_dleq_correctness(
			"1111111111111111111111111111111111111111111111111111111111111111",
			"2222222222222222222222222222222222222222222222222222222222222222",
			"02407feb4a4b8303baf4f84e29a209e0dcfd62e81f88c8edb7675c5a95d90e5c90"
		);
		test_dleq_correctness(
			"4444444444444444444444444444444444444444444444444444444444444444",
			"8888888888888888888888888888888888888888888888888888888888888888",
			"026e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
		);
	}
}
