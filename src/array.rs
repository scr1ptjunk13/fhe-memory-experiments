//! Linear-scan encrypted array.
//!
//! Implements the identity
//!     arr[i] = Σ_{j=0..N-1} 1[i = j] · arr[j]
//! over TFHE ciphertexts as
//!     read(enc_arr, enc_idx) = Σ_j  if_then_else( eq(enc_idx, j), arr[j], 0 ).
//!
//! Touches every slot on every call: O(N) PBS per read, zero
//! access-pattern leakage (the security ceiling other backends trade off
//! against).

use tfhe::prelude::*;
use tfhe::{ClientKey, FheUint8, FheUint32};

pub struct FheArray {
    data: Vec<FheUint8>,
}

impl FheArray {
    pub fn encrypt(plaintext: &[u8], client_key: &ClientKey) -> Self {
        let data = plaintext
            .iter()
            .map(|&v| FheUint8::try_encrypt(v, client_key).expect("FheUint8 encrypt"))
            .collect();
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Linear-scan read at an encrypted index.
    ///
    /// Requires the server key to be set on the current thread via
    /// `tfhe::set_server_key(..)`. Panics if `self` is empty.
    pub fn read(&self, enc_idx: &FheUint32) -> FheUint8 {
        assert!(!self.data.is_empty(), "FheArray::read on empty array");

        let zero = FheUint8::encrypt_trivial(0u8);
        let mut acc = FheUint8::encrypt_trivial(0u8);

        for (j, val_j) in self.data.iter().enumerate() {
            let eq = enc_idx.eq(j as u32);
            let gated = eq.if_then_else(val_j, &zero);
            acc = acc + gated;
        }

        acc
    }
}
