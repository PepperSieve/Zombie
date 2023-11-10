import os

files = {
    'chacha_co_var_idxes': "https://www.dropbox.com/s/k104ep1ywokwcr7/chacha_co_var_idxes?dl=0",
    'chacha_co_term_arr': "https://www.dropbox.com/s/k9bw6eezob3iifi/chacha_co_term_arr?dl=0",
    'chacha_co_inst': "https://www.dropbox.com/s/dh28e52dykkb8ep/chacha_co_inst?dl=0",
    'chacha_amortized_term_arr': "https://www.dropbox.com/s/87l6z2sxqb3bok0/chacha_amortized_term_arr?dl=0",
    'chacha_amortized_var_idxes': "https://www.dropbox.com/s/ge5gai7akwi9p3y/chacha_amortized_var_idxes?dl=0",
    'chacha_co_input_idxes': "https://www.dropbox.com/s/nnlkhk8lzkydufm/chacha_co_input_idxes?dl=0",
    'chacha_co_input_names': "https://www.dropbox.com/s/2g7h8mhfih6alz2/chacha_co_input_names?dl=0",
    'chacha_co_gens': "https://www.dropbox.com/s/ypzp5b666na7xfc/chacha_co_gens?dl=0",
    'chacha_amortized_inst': "https://www.dropbox.com/s/ppm844w1kaxv14w/chacha_amortized_inst?dl=0",
    'chacha_amortized_gens': "https://www.dropbox.com/s/te3mma608lavhd6/chacha_amortized_gens?dl=0",
    'chacha_amortized_input_idxes': "https://www.dropbox.com/s/ln210gh5vech7vv/chacha_amortized_input_idxes?dl=0",
    'chacha_amortized_input_names': "https://www.dropbox.com/s/57dypxn4oqn4t0k/chacha_amortized_input_names?dl=0"
}

for name in files:
    os.system(f"wget {files[name]} -O ./keys/{name}")