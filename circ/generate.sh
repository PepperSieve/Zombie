#!/bin/bash

# ensure command line arg size is provided and assign to var
if [ $# -ne 1 ]; then
    echo 'Usage: '$0' <instance Size>'
    exit 1
fi
size=$1

# print progress
echo 'Generating ChaCha relation, instance, and witness files for message of size '$size'...'

# run_zok template to proper run_zok file
# and ChaCha template to proper ChaCha file
cp ./examples/run_zok_template.rs ./examples/run_zok.rs
cp ./zkmb/ChaCha_template.zok ./zkmb/ChaCha.zok

if [ "$(uname)" == "Darwin" ]; then
    sed -i '.bak' 's/\_MSG_LEN\_/'$size'/g' ./examples/run_zok.rs
    sed -i '.bak' 's/\_MSG_LEN\_/'$size'/g' ./zkmb/ChaCha.zok
else
    sed -i 's/\_MSG_LEN\_/'$size'/g' ./examples/run_zok.rs
    sed -i 's/\_MSG_LEN\_/'$size'/g' ./zkmb/ChaCha.zok
fi

# generate relation, instance, and witness files
$HOME/.cargo/bin/cargo run --release --package circ --example run_zok --features smt

# rename output files
mv ./darpa/000_instance.sieve ./darpa/chacha_$size.ins
mv ./darpa/001_witness.sieve ./darpa/chacha_$size.wit
mv ./darpa/002_relation.sieve ./darpa/chacha_$size.rel

# notify completion
echo 'rel, ins, and wit files generated successfully for size '$size
