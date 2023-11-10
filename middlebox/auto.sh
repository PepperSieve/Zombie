# sudo apt-get update
# sudo apt install coinor-cbc coinor-libcbc-dev build-essential m4 -y
# sudo ip a add 10.0.0.1/24 dev eth0
# git submodule update --init --recursive
cargo build --release
sudo RUST_BACKTRACE=1 ./target/release/middlebox_rust benchmark_async