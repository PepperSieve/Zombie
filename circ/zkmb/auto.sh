# install ZoKrates 0.7.6 first

mkdir tmp
cd tmp
zokrates compile -i ../HKDF.zok
zokrates compute-witness -a 0 5 0 5

cd ..
python3 -m pip install cryptography
python3 hkdf_test.py

# ~out_[0-31] should be the same as output of hkdf_test.py