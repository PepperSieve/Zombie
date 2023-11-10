git pull debug main
cd circ
$HOME/.cargo/bin/cargo build --release
cd ../prover
# sudo ./venv/bin/python main.py benchmark_normal Dot ChaCha 10
# sync
# sudo ./venv/bin/python main.py custom no_precompute should_batch Dot ChaCha trace 10 0.1
# async
# sudo ./venv/bin/python main.py custom no_precompute should_batch Dot ChaCha trace 10 5
sudo ./venv/bin/python main.py no_middlebox Dot ChaCha trace 0