/usr/local/bin/sage scripts/generate_primes.py > class-groups/src/publicly_verifiable_secret_sharing/chinese_remainder_theorem/consts.rs
cargo test --release --all-features --package class_groups --lib reconfiguration::test_helpers::generate_keys_for_test_consts_secp256k1 -- --ignored --exact --nocapture > tmp.rs
sed -e '1,2d' tmp.rs | head -n 8 > class-groups/src/publicly_verifiable_secret_sharing/test_consts.rs
rm tmp.rs
cargo fmt --all