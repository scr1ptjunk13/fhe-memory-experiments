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
    use tfhe::{ConfigBuilder, FheUint8, FheUint32, generate_keys, set_server_key};

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

    #[test]
    fn linear_scan_write_matches_oracle_n8() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let plain: Vec<u8> = vec![17, 3, 200, 0, 99, 42, 255, 7];
        let fresh = 123u8;

        // Write `fresh` at every index in turn, each time starting from the
        // original array. Two assertions per write: the written slot took the
        // new value, and every other slot is byte-equal to the original —
        // untouched-slots-unchanged is the entire point (Phase 3 hardens this
        // same property to noise-indistinguishability against rewinding).
        for i in 0..plain.len() {
            let mut oracle = PlainArray::new(plain.clone());
            let mut enc = FheArray::encrypt(&plain, &client_key);

            let enc_idx =
                FheUint32::try_encrypt(i as u32, &client_key).expect("encrypt index");
            let enc_val = FheUint8::try_encrypt(fresh, &client_key).expect("encrypt value");
            enc.write(&enc_idx, &enc_val);
            oracle.write(i, fresh);

            let got = enc.decrypt(&client_key);
            assert_eq!(
                got[i],
                oracle.read(i),
                "write at {i}: written slot is {}, expected {fresh}",
                got[i]
            );
            for j in (0..plain.len()).filter(|&j| j != i) {
                assert_eq!(
                    got[j], plain[j],
                    "write at {i}: untouched slot {j} changed from {} to {}",
                    plain[j], got[j]
                );
            }
        }
    }

    #[test]
    fn sequential_writes_then_read_matches_oracle() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key);

        let plain: Vec<u8> = vec![17, 3, 200, 0, 99, 42, 255, 7];
        let mut oracle = PlainArray::new(plain.clone());
        let mut enc = FheArray::encrypt(&plain, &client_key);

        // mixed indices, including an overwrite of slot 1
        for (i, v) in [(1usize, 11u8), (6, 250), (1, 12), (0, 0), (4, 77)] {
            let enc_idx =
                FheUint32::try_encrypt(i as u32, &client_key).expect("encrypt index");
            let enc_val = FheUint8::try_encrypt(v, &client_key).expect("encrypt value");
            enc.write(&enc_idx, &enc_val);
            oracle.write(i, v);
            assert_eq!(
                enc.decrypt(&client_key),
                oracle.data,
                "state diverged after write {v} at {i}"
            );
        }

        // read-after-write through the encrypted path, at the overwritten slot
        let enc_idx = FheUint32::try_encrypt(1u32, &client_key).expect("encrypt index");
        let got: u8 = enc.read(&enc_idx).decrypt(&client_key);
        assert_eq!(got, oracle.read(1), "read-after-write at slot 1");
    }
}
