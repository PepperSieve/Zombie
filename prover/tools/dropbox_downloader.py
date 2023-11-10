import os, subprocess

dropbox_download_dict = {
    "chacha_amortized_inst": "xxx", 
    "chacha_amortized_gens": "xxx", 
    "chacha_amortized_term_arr": "xxx", 
    "chacha_amortized_input_idxes": "todo", 
    "chacha_amortized_var_idxes": "todo",
    "chacha_co_inst": "todo",  
    "chacha_co_gens": "todo", 
    "chacha_co_term_arr": "todo", 
    "chacha_co_input_idxes": "todo", 
    "chacha_co_var_idxes": "todo"
}

def get_dropbox_file(file_name, use_dropbox):
    file_path = f'/mydata/{file_name}' 
    if not use_dropbox:
        return file_path
    if not os.path.exists(file_path):
        print(file_path, "not exist")
        download_link = dropbox_download_dict[file_name]
        subprocess.run(['wget', '-O', file_path, download_link])
    return file_path