def SHA256(input_data):
	# 模2³²加法
	X32_add = lambda a, b: (a + b) & 0xFFFFFFFF

	"""
	辅助函数：将4个8位整数合并为一个32位整数（大端序）
	例：0x12, 0x34, 0x56, 0x78 → 0x12345678
	"""
	merge_int = lambda b0, b1, b2, b3: (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

	# 消息填充
	padded_data = []

	for b in input_data:
		padded_data.append(b)

	# 消息长度（位）
	datLen = len(padded_data) * 8

	# 填充一个“0x80”
	padded_data.append(0x80)

	# 填充n个“0x00”
	while not ((len(padded_data) * 8) + 64) % 512 == 0:
		padded_data.append(0x00)

	# 将消息长度附加到末尾（8字节大端序）
	for i in range(8):
		padded_data.append(list(datLen.to_bytes(8, "big"))[i])

	# 定义初始哈希值：前8个素数2...19的平方根的小数部分的前32位
	H0 = 0x6A09E667
	H1 = 0xBB67AE85
	H2 = 0x3C6EF372
	H3 = 0xA54FF53A
	H4 = 0x510E527F
	H5 = 0x9B05688C
	H6 = 0x1F83D9AB
	H7 = 0x5BE0CD19

	# 定义K表：前64个素数2...311的立方根的小数部分的前32位
	K_table = (
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	)

	# 将一个32位整数向右逐位旋转（32位循环右移）
	rotate_right = lambda x, n: (x >> n) | (x << (32 - n))

	# CH（choose）选择器
	CH = lambda x, y, z: (x & y) ^ (~x & z)

	# MAJ（majority）多数函数
	MAJ = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)

	# Σ₀
	BSIG0 = lambda x: rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)

	# Σ₁
	BSIG1 = lambda x: rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)

	# σ₀
	SSIG0 = lambda x: rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)

	# σ₁
	SSIG1 = lambda x: rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)

	# 对每一个512位（64字节）的消息块进行循环
	for i in range(len(padded_data) // 64):
		# 消息扩展
		W_table = [0] * 64# 初始化W表

		# 将W表的前16个元素设置为消息块的内容（从0到15）
		for j in range(16):
			offset = i * 64 + j * 4

			W_table[j] = merge_int(padded_data[offset], padded_data[offset + 1], padded_data[offset + 2], padded_data[offset + 3])

		# 扩展W表（从16到63）
		for j in range(16, 64):
			W_table[j] = X32_add(X32_add(X32_add(SSIG1(W_table[j - 2]), W_table[j - 7]), SSIG0(W_table[j - 15])), W_table[j - 16])

		# 初始化工作变量：将H0...H7赋值给AA...HH
		AA = H0
		BB = H1
		CC = H2
		DD = H3
		EE = H4
		FF = H5
		GG = H6
		HH = H7

		# 64轮的主循环
		for rnd in range(64):
			# 计算临时变量
			T1 = X32_add(X32_add(X32_add(X32_add(HH, BSIG1(EE)), CH(EE, FF, GG)), K_table[rnd]), W_table[rnd])
			T2 = X32_add(BSIG0(AA), MAJ(AA, BB, CC))

			# 更新工作变量
			HH = GG
			GG = FF
			FF = EE
			EE = X32_add(DD, T1)
			DD = CC
			CC = BB
			BB = AA
			AA = X32_add(T1, T2)

		# 更新哈希值
		H0 = X32_add(AA, H0)
		H1 = X32_add(BB, H1)
		H2 = X32_add(CC, H2)
		H3 = X32_add(DD, H3)
		H4 = X32_add(EE, H4)
		H5 = X32_add(FF, H5)
		H6 = X32_add(GG, H6)
		H7 = X32_add(HH, H7)

	# 最终输出
	hashed = [H0, H1, H2, H3, H4, H5, H6, H7]
	final_output = []

	for i in range(0, len(hashed) * 32, 8):
		final_output.append((hashed[i >> 5] >> (24 - i % 32)) & 0xFF)

	return bytes(final_output)

# HMAC SHA-256
def HMAC_SHA256(input_data, key):
	# 初始化ipad和opad
	ipad = [0] * 64
	opad = [0] * 64

	# 密钥长度
	keyLen = len(key)

	# 密钥长度大于64字节，执行一次SHA256
	if keyLen > 64:
		key = SHA256(key)

	# 密钥长度不足64字节，填充n个0x00
	key += b"\x00" * (64 - keyLen)

	# 异或操作
	for i in range(64):
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C

	# 计算HMAC值
	return SHA256(bytes(opad) + SHA256(bytes(ipad) + input_data))


if __name__ == "__main__":
	input_data = "你好，世界".encode("utf-8")

	print(f"\n输入：{input_data.decode("utf-8")}")
	print(f"\nSHA-256值：{SHA256(input_data).hex()}")

	key = "114514".encode("utf-8")

	print(f"\n密钥：{key.decode("utf-8")}")
	print(f"\nHMAC SHA-256值：{HMAC_SHA256(input_data, key).hex()}\n")

"""
SHA256(<原始消息：字节>)
HMAC_SHA256(<原始消息：字节>, <密钥：字节>)
"""