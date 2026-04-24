# 轮常量表：来自线性反馈移位寄存器
rcon = (
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
	0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008
)

# 旋转偏移量表
ROTL_table = (
	(0, 36, 3, 41, 18),
	(1, 44, 10, 45, 2),
	(62, 6, 43, 15, 61),
	(28, 55, 25, 21, 56),
	(27, 20, 39, 8, 14)
)

# Keccak F 置换函数
def Keccak_F(state):
	# 将一个64位整数向左逐位旋转（64位循环左移）
	rotate_left = lambda x, n: ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

	CC = [0] * 5
	DD = [0] * 5

	for rnd in range(24):
		# θ（theta）步骤：扩散
		for i in range(5):
			CC[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]

		for i in range(5):
			DD[i] = CC[(i + 4) % 5] ^ rotate_left(CC[(i + 1) % 5], 1)

			for j in range(5):
				state[i + 5 * j] ^= DD[i]

		# ρ（rho）和π（pi）步骤：分别是循环左移和重新排列
		BB = [0] * 25

		for i in range(5):
			for j in range(5):
				BB[j + 5 * ((2 * i + 3 * j) % 5)] = rotate_left(state[i + 5 * j], ROTL_table[i][j])

		# χ（chi）步骤：混淆
		for i in range(5):
			for j in range(5):
				state[i + 5 * j] = BB[i + 5 * j] ^ (~BB[(i + 1) % 5 + 5 * j] & BB[(i + 2) % 5 + 5 * j])

		# ι（iota）步骤：和轮常量异或
		state[0] ^= rcon[rnd]

# 消息填充函数
def pad_data(input_data, bit_rate, delimited_suffix):
	datLen = len(input_data)

	q = (bit_rate - (datLen * 8 % bit_rate)) // 8

	if q == 1:
		q += bit_rate // 8

	padded_data = [0] * (datLen + q)

	for i in range(datLen):
		padded_data[i] = input_data[i]

	# 添加终止符
	padded_data[datLen] |= delimited_suffix
	padded_data[len(padded_data) - 1] |= 0x80

	return padded_data

# 吸收和挤压函数
def absorb_and_squeeze(input_data, dgstLen, bit_rate, delimited_suffix):
	if not dgstLen % 8 == 0:
		raise ValueError("digest length must be a multiple of 8")

	# 字节率
	byte_rate = bit_rate // 8

	# 填充的原始消息
	padded_data = pad_data(input_data, bit_rate, delimited_suffix)

	# 初始化状态矩阵
	state = [0] * 25

	# 矩阵中的每一个元素都是64位（小端序），大小为1600位（200字节）

	# 吸收阶段
	for offset in range(0, len(padded_data), byte_rate):
		block = padded_data[offset:offset + byte_rate]

		for i in range(len(block) // 8):
			state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")

		Keccak_F(state)

	# 挤压阶段
	final_output = b""

	for ele in state:
		final_output += ele.to_bytes(8, "little")

	# 最终输出
	return final_output[:dgstLen // 8]

# SHA3
def SHA3(input_data, dgstLen):
	if not dgstLen in (224, 256, 384, 512):
		raise ValueError("digest length must be 224, 256, 384, 512 bits")

	return absorb_and_squeeze(input_data, dgstLen, 1600 - (dgstLen * 2), 0x06)

# SHAKE128
SHAKE128 = lambda input_data, dgstLen: absorb_and_squeeze(input_data, dgstLen, 1344, 0x1F)

# SHAKE256
SHAKE256 = lambda input_data, dgstLen: absorb_and_squeeze(input_data, dgstLen, 1088, 0x1F)

# HMAC SHA3
def HMAC_SHA3(input_data, key, dgstLen):
	if not dgstLen in (224, 256, 384, 512):
		raise ValueError("digest length must be 224, 256, 384, 512 bits")

	# SHA3的分组长度的选择（字节）
	block_size = 0

	match dgstLen:
		case 224:
			block_size = 144
		case 256:
			block_size = 136
		case 384:
			block_size = 104
		case 512:
			block_size = 72

	# 初始化ipad和opad
	ipad = [0] * block_size
	opad = [0] * block_size

	# 密钥长度
	keyLen = len(key)

	# 密钥长度大于SHA3的分组长度，执行一次SHA3
	if keyLen > block_size:
		key = SHA3(key, dgstLen)

	# 密钥长度不足SHA3的分组长度，填充n个0x00
	key += b"\x00" * (block_size - keyLen)

	# 异或操作
	for i in range(block_size):
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C

	# 计算HMAC值
	return SHA3(bytes(opad) + SHA3(bytes(ipad) + input_data, dgstLen), dgstLen)


if __name__ == "__main__":
	input_data = "你好，世界".encode("utf-8")

	print(f"\n输入：{input_data.decode("utf-8")}\n")
	print(f"\nSHA3-224值：{SHA3(input_data, 224).hex()}")
	print(f"\nSHA3-256值：{SHA3(input_data, 256).hex()}")
	print(f"\nSHA3-384值：{SHA3(input_data, 384).hex()}")
	print(f"\nSHA3-512值：{SHA3(input_data, 512).hex()}")
	print(f"\nSHAKE128值（输出128位）：{SHAKE128(input_data, 128).hex()}")
	print(f"\nSHAKE128值（输出256位）：{SHAKE128(input_data, 256).hex()}")
	print(f"\nSHAKE256值（输出256位）：{SHAKE256(input_data, 256).hex()}")
	print(f"\nSHAKE256值（输出512位）：{SHAKE256(input_data, 512).hex()}\n")

	key = "114514".encode("utf-8")

	print(f"\n密钥：{key.decode("utf-8")}\n")
	print(f"\nHMAC SHA3-224值：{HMAC_SHA3(input_data, key, 224).hex()}")
	print(f"\nHMAC SHA3-256值：{HMAC_SHA3(input_data, key, 256).hex()}")
	print(f"\nHMAC SHA3-384值：{HMAC_SHA3(input_data, key, 384).hex()}")
	print(f"\nHMAC SHA3-512值：{HMAC_SHA3(input_data, key, 512).hex()}\n")

"""
SHA3：

SHA3(<原始消息：字节>, <摘要长度：正整数>)
HMAC_SHA3(<原始消息：字节>, <密钥：字节>, <摘要长度：正整数>)

SHA3的摘要长度必须为224、256、384、512位




SHAKE128、SHAKE256：

SHAKE128(<原始消息：字节>, <摘要长度：正整数>)
SHAKE256(<原始消息：字节>, <摘要长度：正整数>)

SHAKE128、SHAKE256的摘要长度必须为8的倍数
SHAKE128、SHAKE256不支持HMAC
"""