def my_print(text):
    with open('tmp.rust', 'a') as f:
        f.write(text + '\n')

def zok_type_to_rust(t):
    if t == 'field':
        pass
    elif t[0] == 'u':
        pass
    elif t == 'bool':
        pass
    pass

def zk_ty_to_rust(ty):
    if ty[0] == 'u':
        return ty
    if ty == 'field':
        return 'String'
    if ty == 'bool':
        return 'Bool'
    raise ValueError

def zk_ty_to_mapper_fn(size, ty, name, is_verify):
    if ty == 'String':
        ty = 'field'
    if is_verify:
        ty = 'field'
    ref = '&'
    if ty[0] == 'u':
        ref = ''
    if size == 0:
        return f'\t\tmapper.map_{ty}({ref}self.{name}, "{name}");'
    else:
        return f'\t\tmapper.map_{ty}_arr_padded(&self.{name}, {size}, "{name}");'
    
def print_struct_field(var):
    var_1 = var[1]
    if var[0] > 0:
        my_print(f"\tpub {var[2]}: Vec<{var_1}>,")
    else:
        my_print(f"\tpub {var[2]}: {var_1},")

def print_verifier_witness_struct(circuit, public_vars):
    my_print("#[derive(Deserialize)]")
    my_print(f"pub struct {circuit}VerifierWitness {{")
    for var in public_vars:
        print_struct_field(var)
    my_print(f'\tpub ret: String')
    my_print(f"}}\n")

def print_prover_witness_struct(circuit, public_vars, private_vars):
    my_print("#[derive(Deserialize)]")
    my_print(f"pub struct {circuit}ProverWitness {{")
    vars = public_vars + private_vars
    for var in vars:
        print_struct_field(var)
    my_print(f"}}\n")

def print_verifier_mapper(circuit, public_vars):
    my_print(f"impl Witness for {circuit}VerifierWitness {{\n\tfn to_map(&self) -> WitnessMapper {{\n\t\tlet mut mapper = WitnessMapper::new();")
    for var in public_vars:
        size, ty, name = var
        my_print(zk_ty_to_mapper_fn(size, ty, name, True))
    my_print(f'\t\tmapper.map_field(&self.ret.to_string(), "return");')
    my_print(f"\t\tmapper")
    my_print(f'\t}}\n}}\n')

def print_prover_mapper(circuit, public_vars, private_vars):
    my_print(f"impl Witness for {circuit}ProverWitness {{\n\tfn to_map(&self) -> WitnessMapper {{\n\t\tlet mut mapper = WitnessMapper::new();")
    vars = public_vars + private_vars
    for var in vars:
        size, ty, name = var
        my_print(zk_ty_to_mapper_fn(size, ty, name, False))
    my_print(f"\t\tmapper")
    my_print(f'\t}}\n}}\n')

def generate_witness_struct(circuit, main_signature):
    variables = main_signature.split(', ')
    variables = [v.split(' ') for v in variables]
    # print(f"struct {circuit} {{")
    private_vars = []
    public_vars = []
    for variable in variables:
        ty = variable[-2]
        size = 0
        # hacky way to detect array
        if '[' in ty:
            ty_size = ty.split('[')
            ty = ty_size[0] 
            size = int(ty_size[1][:-1])
            ty = zk_ty_to_rust(ty)
        else:
            ty = zk_ty_to_rust(ty)
        if len(variable) == 2:
            public_vars.append((size, ty, variable[-1]))
        elif len(variable) == 3:
            private_vars.append((size, ty, variable[-1]))
        else:
            print("Unexpected length of variable", variable)
    print_verifier_witness_struct(circuit, public_vars)
    # verifier witness should include return as input
    print_verifier_mapper(circuit, public_vars)
    print_prover_witness_struct(circuit, public_vars, private_vars)
    print_prover_mapper(circuit, public_vars, private_vars)


if __name__ == '__main__':
    with open('tmp.rust', 'w') as f:
        f.write('')
    generate_witness_struct('DotChaChaAmortizedUnpack', "private u8[255] pad, field comm_pad, u8[255] dns_ct, field root, private u8[255] left_domain_name, private u8[255] right_domain_name, private u32 left_index, private u32 right_index, private field[21] left_path_array, private field[21] right_path_array, private u64 left_dir, private u64 right_dir")