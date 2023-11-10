# run this in prover folder
mkdir data
mkdir tmp
mkdir keys

# install prerequisites
sudo apt-get update
sudo apt-get install python3-venv coinor-cbc coinor-libcbc-dev build-essential m4 wget python3-pip -y

git submodule update --init --recursive

# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
cd ../circ
$HOME/.cargo/bin/cargo build --release
cd ../prover

# configure python package
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install wheel
./venv/bin/pip install ./tlslite-ng-0.8.0-alpha40
./venv/bin/pip install cryptography
./venv/bin/pip install dnslib
./venv/bin/pip install requests
./venv/bin/pip install chacha20poly1305
./venv/bin/pip install numpy
./venv/bin/pip install psutil

sudo ip r add 8.8.8.8 via 192.168.0.1