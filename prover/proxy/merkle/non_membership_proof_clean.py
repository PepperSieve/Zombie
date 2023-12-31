# from .poseidon_hash import PoseidonHashGenerator
import os
import time
import bisect
import numpy as np

blocklist_file_name = "pi_blocklist_all.list.txt"
# hash_generator = PoseidonHashGenerator('dalek')

# read blacklist from file
def parseFile(filename):
	with open(filename, 'r') as readFile:
		lines = readFile.readlines()
				
	return lines


# turn string array to uint2040 array
# i.e. "abc" = 97+98*256+99*65536 = 6513249
# each string is 255byte, so each integer will be uint2040 (255*8=2040)
def string_array_to_uint2040_array(set_input):
	set_bytes = []
	for item in set_input:
		element_byte = bytes(item,'utf-8')
		set_bytes.append(int.from_bytes(element_byte, "little"))

	return set_bytes

# turn a string to padded uint_8[255] array (byte array)
def string_to_padded_uint8_array(input_string):
	bytes_array = bytes(input_string,'utf-8')
	padded_int_array =[]
	length = len(bytes_array)
	for i in range(0, 255):
		if (i < length):
			padded_int_array.append(bytes_array[i])
		else:
			padded_int_array.append(0)
	return padded_int_array

# covert large integer to Fp[8] array, each is 253bit limb
# note: Though input is uint2040, valid input will only be 2024bit (253bytes)!!! 
def convert_uint2040_to_Fp(long_input):
	Fp_array = []
	for i in range(0,8):
		Fp_array.append(long_input%(1<<252))
		long_input >>= 253

	return Fp_array

# convert a large integer array to Fp[8] array
# i.e. each uint2040 will be Fp[8]
def convert_uint2040_array_to_Fp8_array(set_input):
	Fp_array = []
	for element in set_input:
		Fp_array.append(convert_uint2040_to_Fp(element))

	return Fp_array

# Fp[8] input for Poseidon hash
def Fp8_to_hash(Fp_array):
	output_hash = []
	start = time.time()
	print("compute Fp8 to hash")
	for element in Fp_array:
		output_hash.append(hash_generator.poseidon_hash(element))
	end = time.time()
	print("Fp8 to hash time", end-start)

	return output_hash

# turn string array to hash array
# Firstly, turn string array into a uint2040 array (i.e. each string will be one uint2040)
# Secondly, turn uint2040 array into Fp[8] array (i.e. each uint2040 will be Fp[8] to fit into Poseidon hash)
# Thirdly, Poseidon hash each Fp[8] to get the output hash array 
def blocklist_to_hash_leaves(set_input):
	int_array = string_array_to_uint2040_array(set_input)
	Fp_array = convert_uint2040_array_to_Fp8_array(int_array)
	output_hash = Fp8_to_hash(Fp_array)

	return output_hash

# compute the length of common substring
def string_common_len(string1, string2):
	length = min(len(string1), len(string2))

	for i in range(0, length):
		if string1[i]==string2[i]:
			continue
		else:
			return i
	return length

# sort in wildcard
def wildcard_sort(input_array):
	# preprocess, add 0 and 255 as the first and last leaf in Merkle Tree
	input_array = [chr(0)]+input_array+[chr(255)]
	
	# add "." to the blocklist and reverse the string (match from the end)
	length = len(input_array)
	for i in range(0, length):
		input_array[i] = "."+input_array[i]
		input_array[i] = input_array[i][::-1]

	# sort the list (compare character by character)
	input_array.sort()

	return input_array

# compute merkle tree height
def merkle_tree_height(input_length):
	input_length = int(input_length)
	bit_length = input_length.bit_length()
	if bit_length == 0:
		return 0
	elif (1<<(bit_length-1)) == (input_length):
		return bit_length-1
	else:
		return bit_length

# compute merkle tree root, merkle tree, height 
def compute_merkle_tee(set_input):
	height = merkle_tree_height(len(set_input))
	print("height", height)
	complete_input = set_input + [0 for i in range(0, (1<<height)-len(set_input))]
	
	interval = height
	start_index = 0

	for i in range(0, height):
		for j in range(start_index, start_index + (1<<interval), 2):
			complete_input.append(hash_generator.poseidon_hash([complete_input[j],complete_input[j+1]]))
		start_index += 1<<interval
		interval = interval-1

	return (complete_input[-1], complete_input, height)

# get merkle tree path
def get_merkle_tree_path(merkle_tree, height, dirSelection):
	dirSelection = int(dirSelection)
	auth_path = []
	start_index = 0
	interval = height
	for i in range(0, height):
		if (dirSelection%2) == 1:
			auth_path.append(merkle_tree[start_index + dirSelection - 1])
		else:
			auth_path.append(merkle_tree[start_index + dirSelection + 1])

		start_index += (1<<interval)
		interval = interval-1
		dirSelection = dirSelection>>1

	return auth_path

# verifiy merkle tree path
def verify_merkle_tree(leaf, auth_path, dirSelection, height, root):
	dirSelection = int(dirSelection)
	currentDigest = leaf

	for i in range(0, height):
		for j in range(0,2):
			if (dirSelection%2) == 1:
				inputToNextHash = [auth_path[i],currentDigest]
			else:
				inputToNextHash = [currentDigest, auth_path[i]]
		
		currentDigest = hash_generator.poseidon_hash(inputToNextHash)
		dirSelection = dirSelection>>1

	print("currentDigest is", currentDigest)
	return (root == currentDigest)

# verifiy merkle tree path
def verify_wildcard_merkle_tree(leaf, auth_path, dirSelection, height, root):
	dirSelection = int(dirSelection)
	currentDigest = leaf

	for i in range(0, height):
		for j in range(0,2):
			if (dirSelection%2) == 1:
				inputToNextHash = [auth_path[i],currentDigest]
			else:
				inputToNextHash = [currentDigest, auth_path[i]]
		
		currentDigest = hash_generator.poseidon_hash(inputToNextHash)
		dirSelection = dirSelection>>1

	print("currentDigest is", currentDigest)
	return (root == currentDigest)

def wildcard_non_membership_preprocess(leaf, input_array):

	# reverse input string
	leaf = "."+leaf
	leaf = leaf[::-1]
	input_domain_name = leaf

	# preprocess the input array (add ".", reverse and sort)
	input_array = wildcard_sort(input_array)

	# Find the adjacent leaf leaf and right leaf
	length = len(input_array)
	for i in range(0, length):
		if (leaf < input_array[i]):
			left_leaf = input_array[i-1]
			right_leaf = input_array[i]
			break
		elif (leaf == input_array[i]):
			print("invalid input in the blakclist!!!")
			return

	# Find left_index and right_index
	left_index = string_common_len(left_leaf, leaf)
	right_index = string_common_len(leaf, right_leaf)

	# compute merkle tree usng blacklist array as input
	print("computing the hash of leaves.....")
	input_array = blocklist_to_hash_leaves(input_array)
	print("compute hash of leaves done")
	merkle_tree = compute_merkle_tee(input_array)
	print("compute merkle tree")

	# merkle tree root
	root = merkle_tree[0]
	# the whole merkle tree
	merkle_tree_structure = merkle_tree[1]
	# merkle tree height
	height = merkle_tree[2]

	# write the generated merkle tree to a file (preprocessed result)
	f=open("wildcard_new_pre.txt","w")
	for line in merkle_tree_structure:
		f.write(str(line)+'\n')
	f.close()

	# generate left and right path, the directionSelector will be i-1 and i
	authPath_left = get_merkle_tree_path(merkle_tree_structure, height, i-1)
	authPath_right = get_merkle_tree_path(merkle_tree_structure, height, i)

	# output witness file
	write_witness = {}
	write_witness['input_domain_name_wildcard'] = string_to_padded_uint8_array(input_domain_name)
	write_witness['root'] = root
	write_witness['left_domain_name'] = string_to_padded_uint8_array(left_leaf)
	write_witness['right_domain_name'] = string_to_padded_uint8_array(right_leaf)
	write_witness['authPath_left'] = authPath_left
	write_witness['authPath_left_dir'] = i-1
	write_witness['authPath_right'] = authPath_right
	write_witness['authPath_right_dir'] = i
	write_witness['left_index'] = left_index
	write_witness['right_index'] = right_index

	return write_witness


def wildcard_non_membership_witness(leaf, blocklist_path, wildcard_pre_path):

	start = time.time()
	input_array = parseFile(blocklist_path)
	input_array = wildcard_sort(input_array)
	end = time.time()
	print("parse and sort blocklist time:", end-start)

	# reverse input string
	leaf = "."+leaf
	leaf = leaf[::-1]
	input_domain_name = leaf

	# Find the adjacent leaf leaf and right leaf
	height = merkle_tree_height(len(input_array))
	length = (1<<height)
	for i in range(0, length):
		if (leaf < input_array[i]):
			left_leaf = input_array[i-1]
			right_leaf = input_array[i]
			break
		elif (leaf == input_array[i]):
			print("invalid input in the blakclist!!!")
			return
			
	# Find left_index and right_index
	left_index = string_common_len(left_leaf, leaf)
	right_index = string_common_len(leaf, right_leaf)
	print(left_index, left_leaf, right_index, right_leaf)

	# read merkle tree from preprocessed file
	start = time.time()
	input_array = parseFile(wildcard_pre_path)
	end = time.time()
	print("parse merkle tree file time:", end-start)

	# the elements read directly from the preprocessed merkle tree file are string elements, we need int!
	length = len(input_array)
	start = time.time()
	for j in range(0, length):
		input_array[j] = int(input_array[j])
	end = time.time()
	print("convert to int time:", end-start)

	merkle_tree_structure = input_array
	root = merkle_tree_structure[-1]

	# generate left and right path, the directionSelector will be i-1 and i
	start = time.time()
	authPath_left = get_merkle_tree_path(merkle_tree_structure, height, i-1)
	authPath_right = get_merkle_tree_path(merkle_tree_structure, height, i)
	end = time.time()

	# output witness file
	write_witness = {}
	write_witness['input_domain_name_wildcard'] = string_to_padded_uint8_array(input_domain_name)
	write_witness['root'] = root
	write_witness['left_domain_name'] = string_to_padded_uint8_array(left_leaf)
	write_witness['right_domain_name'] = string_to_padded_uint8_array(right_leaf)
	write_witness['authPath_left'] = authPath_left
	write_witness['authPath_left_dir'] = i-1
	write_witness['authPath_right'] = authPath_right
	write_witness['authPath_right_dir'] = i
	write_witness['left_index'] = left_index
	write_witness['right_index'] = right_index

	# write witness to the txt file
	result = ''
	for item in write_witness['input_domain_name_wildcard']:
		result += str(item)+'\n'

	result += str(root)+'\n'

	for item in write_witness['left_domain_name']:
		result += str(item)+'\n'
	
	for item in write_witness['right_domain_name']:
		result += str(item)+'\n'

	for item in authPath_left:
		result += str(item)+'\n'
	for item in authPath_right:
		result += str(item)+'\n'

	result += str(i-1)+'\n'
	result += str(i)+'\n'
	result += str(left_index)+'\n'
	result += str(right_index)+'\n'

	return result
	

class MerkelWitnessGenerator:
	def __init__(self, sorted_blocklist_path, wildcard_pre_path):
		start = time.time()
		input_array = np.load(sorted_blocklist_path, allow_pickle=True)
		end = time.time()
		print("parse and sort blocklist time:", end-start)
		# input_array is overrided later
		self.input_array = input_array

		# read merkle tree from preprocessed file
		start = time.time()
		merkle_tree_structure = np.load(wildcard_pre_path, allow_pickle=True)
		end = time.time()
		print("parse merkle tree file time:", end-start)

		self.merkle_tree_structure = merkle_tree_structure
		self.root = self.merkle_tree_structure[-1]

	def generate(self, leaf):
		# reverse input string
		leaf = "."+leaf
		leaf = leaf[::-1]
		input_domain_name = leaf

		# Find the adjacent leaf leaf and right leaf
		height = merkle_tree_height(len(self.input_array))
		length = (1<<height)
		i = bisect.bisect_right(self.input_array, leaf)
		try:
			# We assume i can not be 0, but it depends on the blocklist given
			left_leaf = self.input_array[i - 1]
			right_leaf = self.input_array[i]
			if i - 1 >= 0 and self.input_array[i - 1] == leaf:
				print("invalid input in the blocklist!!!!")
				return
		except Exception as e:
			print("binary search error", e)
				
		# Find left_index and right_index
		left_index = string_common_len(left_leaf, leaf)
		right_index = string_common_len(leaf, right_leaf)

		# generate left and right path, the directionSelector will be i-1 and i
		start = time.time()
		authPath_left = get_merkle_tree_path(self.merkle_tree_structure, height, i-1)
		authPath_right = get_merkle_tree_path(self.merkle_tree_structure, height, i)
		end = time.time()

		# output witness file
		witness = {}
		witness['root'] = str(self.root)
		witness['left_domain_name'] = [ord(c) for c in left_leaf]
		witness['right_domain_name'] = [ord(c) for c in right_leaf]
		witness['left_path_array'] = [str(i) for i in authPath_left]
		witness['left_dir'] = i-1
		witness['right_path_array'] = [str(i) for i in authPath_right]
		witness['right_dir'] = i
		witness['left_index'] = left_index
		witness['right_index'] = right_index
		return witness

if __name__=='__main__':
	# input_array = parseFile("dalek_blocklist.txt")
	# print("parse done")
	# return_value = wildcard_non_membership_preprocess("google.com", input_array)
	# print(return_value)

	witness_generator = MerkelWitnessGenerator('dalek_blocklist_wildcard_sorted.npy', 'merkle_tree_structure.npy')
	print(witness_generator.generate('amazon.com'))