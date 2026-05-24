//! fhe-memory-lab — encrypted memory primitives on top of tfhe-rs.
//!
//! Day 1: linear-scan `read` over an encrypted index, verified against a
//! plaintext oracle. See `array::FheArray::read` for the math.

pub mod array;
pub mod oracle;

pub use array::FheArray;
pub use oracle::PlainArray;

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::prelude::*;
    use tfhe::{ConfigBuilder, FheUint32, generate_keys, set_server_key};

    #[test]
    fn linear_scan_read_matches_oracle_n8() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let plain: Vec<u8> = vec![17, 3, 200, 0, 99, 42, 255, 7];
        assert_eq!(plain.len(), 8);

        let oracle = PlainArray::new(plain.clone());
        let enc = FheArray::encrypt(&plain, &client_key);

        for i in 0..plain.len() {
            let enc_idx =
                FheUint32::try_encrypt(i as u32, &client_key).expect("encrypt index");
            let got_enc = enc.read(&enc_idx);
            let got: u8 = got_enc.decrypt(&client_key);
            assert_eq!(
                got,
                oracle.read(i),
                "linear-scan read mismatch at index {i}: got {got}, oracle {}",
                oracle.read(i)
            );
        }
    }
}
