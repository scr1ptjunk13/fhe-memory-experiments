//! Rewind probe: is a tfhe-rs server-side write deterministic under rewind?
//!
//! Snapshot an encrypted array, then run the *identical* write(idx=3, val=123)
//! k=3 times — deserializing the snapshot fresh each run, same input
//! ciphertexts — and diff every slot's ciphertext bytes across runs.
//!
//! Identical bytes everywhere ⇒ the evaluation is deterministic: a rewinding
//! evaluator learns nothing new from re-running (but also can't be stopped by
//! noise). Differing bytes ⇒ server-side ops inject randomness, and *where*
//! they differ is exactly what a k-rewind evaluator gets to correlate.
//! Either answer is the opening data point for leakage-question.md.

use fhe_memory_lab::FheArray;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint8, FheUint32, generate_keys, set_server_key};

const K: usize = 3;

fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let plain: Vec<u8> = vec![17, 3, 200, 0, 99, 42, 255, 7];
    let snapshot =
        bincode::serialize(&FheArray::encrypt(&plain, &client_key).data).expect("serialize");
    let idx = FheUint32::try_encrypt(3u32, &client_key).expect("encrypt index");
    let val = FheUint8::try_encrypt(123u8, &client_key).expect("encrypt value");

    // runs[k][slot] = serialized ciphertext bytes after run k's write
    let mut runs: Vec<Vec<Vec<u8>>> = Vec::new();
    for k in 0..K {
        let mut arr = FheArray {
            data: bincode::deserialize(&snapshot).expect("deserialize"),
        };
        arr.write(&idx, &val);
        runs.push(
            arr.data
                .iter()
                .map(|c| bincode::serialize(c).expect("serialize slot"))
                .collect(),
        );
        eprintln!("run {} done", k + 1);
    }

    println!("\nwrite(idx=3, val=123) rewound {K} times from one snapshot:\n");
    println!("slot | run1==run2 | run2==run3");
    println!("-----|------------|-----------");
    for s in 0..plain.len() {
        println!(
            "{:>4} | {:>10} | {:>10}",
            s,
            runs[0][s] == runs[1][s],
            runs[1][s] == runs[2][s]
        );
    }
}
