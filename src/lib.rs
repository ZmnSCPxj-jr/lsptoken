mod basics;
pub(crate) mod simple;

use secp256k1;
use secp256k1::Error;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use secp256k1::Verification;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

fn secretkey_to_scalar(sk: secp256k1::SecretKey) -> secp256k1::Scalar {
	secp256k1::Scalar::from_be_bytes(sk.as_ref().clone()).expect("valid secret keys are valid scalars")
}

fn unblind_err<Ctx: Verification>(ctx: &Secp256k1<Ctx>, c: PublicKey, b: SecretKey, s: PublicKey) -> Result<PublicKey, Error> {
	let neg_b = b.negate();
	let neg_b_s = s.mul_tweak(ctx, &secretkey_to_scalar(neg_b))?;
	c.combine(&neg_b_s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
