# RUSTFLAGS=-Awarnings cargo build --release --example run_zok
# # limit memory usage
# sudo RUST_BACKTRACE=1 systemd-run --scope -p MemoryLimit=16G ./target/release/examples/run_zok

# cargo build --release --example run_zok
# sudo perf record --call-graph dwarf ./target/release/examples/run_zok
sudo perf record --call-graph dwarf ./target/debug/deps/circ_zkmb-c9a4d49e2909c4c9 -- tests::it_works
sudo perf script --no-inline -i perf.data > tmp/run_zok-`date +%F-%T`.txt

# cargo build --release
# python3 tmp/test.py

# run_zok
# cargo run --release --package circ --example run_zok --features smt -- shaRound