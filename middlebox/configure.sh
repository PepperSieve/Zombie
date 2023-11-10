mkdir keys
mkdir tmp

sudo apt-get update
sudo apt install coinor-cbc coinor-libcbc-dev build-essential m4 curl wget -y
git submodule update --init --recursive
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
$HOME/.cargo/bin/cargo build --release
# sudo ./target/release/middlebox_rust benchmark_sync DotChaChaAmortized DotChaChaChannelOpen