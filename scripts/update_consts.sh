cargo test --release --all-features --package class_groups --lib dkg::test_helpers::generate_keys_for_test_consts -- --ignored --exact --nocapture > tmp.rs
sed -e '1,2d' tmp.rs | head -n 8 > class-groups/src/publicly_verifiable_secret_sharing/test_consts.rs
rm tmp.rs
cargo fmt --all