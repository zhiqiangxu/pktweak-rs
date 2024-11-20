use core::panic;

use crate::types;
use blst::min_sig::SecretKey;
use blst::{
    blst_bendian_from_scalar, blst_scalar, blst_scalar_from_be_bytes, blst_sk_add_n_check,
    blst_sk_sub_n_check,
};
use num_bigint::{BigInt, Sign};

pub struct Tweaker {
    dst: Vec<u8>,
    tweaked_pk: Option<SecretKey>,
    tweak_pk: Option<SecretKey>,
}

pub fn new_treaker(dst: Vec<u8>) -> Tweaker {
    Tweaker {
        dst: dst,
        tweaked_pk: None,
        tweak_pk: None,
    }
}

impl types::Tweaker for Tweaker {
    fn tweak(&self, real_pk: BigInt, tweak: BigInt) -> BigInt {
        let (_, real_bs) = real_pk.to_bytes_be();
        let (_, tweak_bs) = tweak.to_bytes_be();

        let mut tweaked_sk = blst_scalar::default();
        let mut real_sk = blst_scalar::default();
        let mut tweak_sk = blst_scalar::default();

        unsafe {
            if !blst_scalar_from_be_bytes(&mut real_sk, real_bs.as_ptr(), real_bs.len()) {
                panic!("invalid real_pk");
            }
            if !blst_scalar_from_be_bytes(&mut tweak_sk, tweak_bs.as_ptr(), tweak_bs.len()) {
                panic!("invalid tweak");
            }
            blst_sk_add_n_check(&mut tweaked_sk, &real_sk, &tweak_sk);

            let mut sk_out = [0; 32];
            blst_bendian_from_scalar(sk_out.as_mut_ptr(), &tweaked_sk);
            return BigInt::from_bytes_be(Sign::Plus, &sk_out);
        }
    }

    fn initialize(&mut self, tweaked_pk: BigInt, tweak: BigInt) -> Result<(), types::Error> {
        let (_, tweaked_bs) = tweaked_pk.to_bytes_be();
        let (_, tweak_bs) = tweak.to_bytes_be();
        let tweaked_pk = SecretKey::from_bytes(&tweaked_bs).unwrap();
        let tweak_pk = SecretKey::from_bytes(&tweak_bs).unwrap();

        self.tweaked_pk = Some(tweaked_pk);
        self.tweak_pk = Some(tweak_pk);
        Ok(())
    }

    fn sign(&self, hash: &[u8]) -> Result<types::Signature, types::Error> {
        if self.tweak_pk.is_none() {
            return Err("should call Initialize first".to_string());
        }

        if let Some(tweak_pk) = self.tweak_pk.as_ref() {
            if let Some(tweaked_pk) = self.tweaked_pk.as_ref() {
                let tweak_bs = tweak_pk.serialize();
                let tweaked_bs = tweaked_pk.serialize();

                let mut tweaked_sk = blst_scalar::default();
                let mut real_sk = blst_scalar::default();
                let mut tweak_sk = blst_scalar::default();
                let mut sk_out = [0; 32];

                unsafe {
                    if !blst_scalar_from_be_bytes(
                        &mut tweaked_sk,
                        tweaked_bs.as_ptr(),
                        tweaked_bs.len(),
                    ) {
                        panic!("invalid real_pk");
                    }
                    if !blst_scalar_from_be_bytes(&mut tweak_sk, tweak_bs.as_ptr(), tweak_bs.len())
                    {
                        panic!("invalid tweak");
                    }
                    blst_sk_sub_n_check(&mut real_sk, &tweaked_sk, &tweak_sk);
                    blst_bendian_from_scalar(sk_out.as_mut_ptr(), &real_sk);
                }

                let real_pk = SecretKey::from_bytes(&sk_out).unwrap();
                let sig = real_pk.sign(hash, &self.dst, &[]);
                return Ok(types::Signature::BLSSUPRSig(sig));
            }
        }

        return Err("bug".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tweaker;
    use rand::Rng;

    #[test]
    fn it_works() {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let mut rng = rand::thread_rng();
        let random_bytes1: [u8; 32] = rng.gen();
        let random_bytes2: [u8; 32] = rng.gen();
        let mut tweaker = new_treaker(dst.into());
        let real_sk = SecretKey::key_gen(&random_bytes1, &[]).unwrap();
        let tweak_sk = SecretKey::key_gen(&random_bytes2, &[]).unwrap();
        let real_pk = real_sk.sk_to_pk();

        let tweaked_sk = tweaker.tweak(
            BigInt::from_bytes_be(Sign::Plus, &real_sk.serialize()),
            BigInt::from_bytes_be(Sign::Plus, &tweak_sk.serialize()),
        );

        tweaker
            .initialize(
                tweaked_sk,
                BigInt::from_bytes_be(Sign::Plus, &tweak_sk.serialize()),
            )
            .unwrap();

        let msg = vec![1];
        let sig = tweaker.sign(&msg).unwrap();
        let types::Signature::BLSSUPRSig(sig) = sig;
        let err = sig.verify(true, &msg, dst, &[], &real_pk, true);
        assert_eq!(err, blst::BLST_ERROR::BLST_SUCCESS);
    }
}
