use blst::min_sig::Signature as BLSSignature;
use num_bigint::BigInt;

pub enum Signature {
    BLSSUPRSig(BLSSignature),
    // ECDSAEthSig(Vec<u8>),
    // ECDSAStdSig(ECDSAStdSig),
}

// pub struct ECDSAStdSig {
//     r: BigInt,
//     s: BigInt,
// }

pub type Error = String;

pub trait Tweaker {
    fn tweak(&self, real_pk: BigInt, tweak: BigInt) -> BigInt;
    fn initialize(&mut self, tweaked_pk: BigInt, tweak: BigInt) -> Result<(), Error>;
    fn sign(&self, hash: &[u8]) -> Result<Signature, Error>;
}
