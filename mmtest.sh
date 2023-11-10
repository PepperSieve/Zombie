git pull debug main --recursive
cd middlebox_rust
$HOME/.cargo/bin/cargo build --release
if [ "$1" == "sync" ]; then
    sudo ./target/release/middlebox_rust benchmark_sync Dot ChaCha "$2" true
else
    sudo ./target/release/middlebox_rust benchmark_async Dot ChaCha 1 true
fi