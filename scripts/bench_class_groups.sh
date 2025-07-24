RUST_BACKTRACE=1 cargo test --package class_groups --release --features benchmarking --lib dkg::benches::benchmark -- --nocapture --exact --ignored  | tee bench_class_groups_dkg.txt
RUST_BACKTRACE=1 cargo test --package class_groups --release --features benchmarking --lib reconfiguration::benches::benchmark -- --nocapture --exact --ignored | tee bench_class_groups_reconfiguration.txt
