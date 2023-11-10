import os, subprocess

dropbox_download_dict = {
    "co_doh_gens": "https://www.dropbox.com/s/9g24gyrwdajd92z/co_doh_gens?dl=0",
    "co_doh_inst": "https://www.dropbox.com/s/vo7zlqw5pm58vaq/co_doh_inst?dl=0",
    "co_doh_pk": "https://www.dropbox.com/s/y4mvkrga9m3uu5m/co_doh_pk?dl=0",
    "co_doh_pvk": "https://www.dropbox.com/s/8ty4p2i9wxscqim/co_doh_pvk?dl=0",
    "co_dot_gens": "https://www.dropbox.com/s/z9h1nj2856le7ml/co_dot_gens?dl=0",
    "co_dot_inst": "https://www.dropbox.com/s/6rsf8xqg03hihhk/co_dot_inst?dl=0",
    "co_dot_pk": "https://www.dropbox.com/s/wl13ydfgbrfn01l/co_dot_pk?dl=0",
    "co_dot_pvk": "https://www.dropbox.com/s/q0qxfopm2g9rpf4/co_dot_pvk?dl=0",
    "doh_gens": "https://www.dropbox.com/s/1sj2xf7m59vk3mz/doh_gens?dl=0",
    "doh_inst": "https://www.dropbox.com/s/qtu4ovocdsd76ol/doh_inst?dl=0",
    "doh_pk": "https://www.dropbox.com/s/6wwhy5fbrlaoinp/doh_pk?dl=0",
    "doh_pvk": "https://www.dropbox.com/s/da7teeoi7mcdxh6/doh_pvk?dl=0",
    "dot_gens": "https://www.dropbox.com/s/h9vodrxkt2btncz/dot_gens?dl=0",
    "dot_inst": "https://www.dropbox.com/s/78tgg757oo801a5/dot_inst?dl=0",
    "dot_pk": "https://www.dropbox.com/s/qdu5gwl9sflfdwv/dot_pk?dl=0",
    "dot_pvk": "https://www.dropbox.com/s/atorz75ishxdily/dot_pvk?dl=0"
}

def get_dropbox_file(file_name, use_dropbox):
    file_path = f'/mydata/{file_name}' 
    if not use_dropbox:
        return file_path
    if not os.path.exists(file_path):
        download_link = dropbox_download_dict[file_name]
        subprocess.run(['wget', '-O', file_path, download_link])
    return file_path