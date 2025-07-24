cargo test --package class_groups --release --features benchmarking,parallel --lib dkg::benches::benchmark -- --nocapture --exact --ignored | tee bench_class_groups_dkg_parallel.txt
cargo test --package class_groups --release --features benchmarking,parallel --lib reconfiguration::benches::benchmark -- --nocapture --exact --ignored | tee bench_class_groups_reconfiguration_parallel.txt
