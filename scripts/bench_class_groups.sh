cargo test --package class_groups --release --features benchmarking --lib dkg::benches::benchmark -- --nocapture --exact --ignored  | tee bench_class_groups_dkg.txt
cargo test --package class_groups --release --features benchmarking --lib reconfiguration::benches::benchmark -- --nocapture --exact --ignored | tee bench_class_groups_reconfiguration.txt
