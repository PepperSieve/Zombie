from non_membership_testing import poseidon_constants_dalek

with open('tmp_cons', 'w') as f:
    f.write("const field[9][639] POSEIDON_C = [\n")
    for t in range(2, 10):
        nums = poseidon_constants_dalek.POSEIDON_C(t)
        f.write("    [\n")
        for num in nums:
            f.write("      " + str(num) + ",\n")
        left = 639 - len(nums)
        if left > 0:
            f.write(f"      ...[0; {left}]\n")
        elif left < 0:
            raise IndexError
        if t == 9:
            f.write("    ]\n")
        else:
            f.write("    ],\n")
    f.write("  ]\n\n")
    size = 9
    f.write(f"const field[9][{size}][{size}] POSEIDON_M = [")
    for t in range(2, 10):
        arrs = poseidon_constants_dalek.POSEIDON_M(t)
        f.write("    [\n")
        for arr in arrs:
            f.write("      [\n")
            for num in arr:
                f.write(f"        {num},\n")
            left_zeros = size - len(arr)
            if left_zeros < 0:
                print(left_zeros, len(arr)) 
                raise IndexError
            if left_zeros > 0:
                f.write("      ")
                for i in range(left_zeros):
                    if i == left_zeros - 1:
                        f.write("0\n")
                    else:
                        f.write("0, ")
            f.write("      ],\n")
        left = size - len(arrs)
        if left > 0:
            f.write(f"      ...[[0; {size}]; {left}]\n")
        elif left < 0:
            raise IndexError
        f.write("    ],\n")
    f.write("  ]")