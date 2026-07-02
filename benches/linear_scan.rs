//! Criterion benchmarks for linear-scan read/write at N ∈ {8..1024}.
//!
//! Dumps per-N mean times to bench-results.csv at the end by reading
//! criterion's own estimates.json — no fancy exporter.

use criterion::{BenchmarkId, Criterion};
use fhe_memory_lab::FheArray;
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, FheUint8, FheUint32, generate_keys, set_server_key};

const NS: &[usize] = &[8, 16, 32, 64, 128, 256, 1024];

// ponytail: deterministic xorshift instead of a rand dev-dep; reproducible runs for free
fn random_bytes(n: usize) -> Vec<u8> {
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15 ^ n as u64;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    for &n in NS {
        let plain = random_bytes(n);
        let enc = FheArray::encrypt(&plain, &client_key);
        let idx = FheUint32::try_encrypt((n / 2) as u32, &client_key).expect("encrypt index");
        let val = FheUint8::try_encrypt(123u8, &client_key).expect("encrypt value");

        c.bench_with_input(BenchmarkId::new("read", n), &n, |b, _| {
            b.iter(|| enc.read(&idx))
        });

        let mut enc_mut = FheArray::encrypt(&plain, &client_key);
        c.bench_with_input(BenchmarkId::new("write", n), &n, |b, _| {
            b.iter(|| enc_mut.write(&idx, &val))
        });
    }

    c.final_summary();
    dump_csv().expect("dump bench-results.csv");
}

fn dump_csv() -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create("bench-results.csv")?;
    writeln!(f, "op,n,mean_ns")?;
    for op in ["read", "write"] {
        for &n in NS {
            let path = format!("target/criterion/{op}/{n}/new/estimates.json");
            let json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            let mean_ns = json["mean"]["point_estimate"]
                .as_f64()
                .unwrap_or_else(|| panic!("no mean in {path}"));
            writeln!(f, "{op},{n},{mean_ns}")?;
        }
    }
    Ok(())
}
