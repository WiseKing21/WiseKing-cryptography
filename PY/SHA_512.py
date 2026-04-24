def SHA512(input_data):
	# 模2⁶⁴加法
	X64_add = lambda a, b: (a + b) & 0xFFFFFFFFFFFFFFFF

	"""
	辅助函数：将8个8位整数合并为一个64位整数（大端序）
	例：0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0x0F → 0x123456789ABCDE0F
	"""
	merge_int = lambda b0, b1, b2, b3, b4, b5, b6, b7: (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) | (b4 << 24) | (b5 << 16) | (b6 << 8) | b7

	# 消息填充
	padded_data = []

	for b in input_data:
		padded_data.append(b)

	# 消息长度（位）
	datLen = len(padded_data) * 8

	# 填充一个“0x80”
	padded_data.append(0x80)

	# 填充n个“0x00”
	while not ((len(padded_data) * 8) + 128) % 1024 == 0:
		padded_data.append(0x00)

	# 将消息长度附加到末尾（16字节大端序）
	for i in range(16):
		padded_data.append(list(datLen.to_bytes(16, "big"))[i])

	# 定义初始哈希值：前8个素数2...19的平方根的小数部分的前64位
	H0 = 0x6A09E667F3BCC908
	H1 = 0xBB67AE8584CAA73B
	H2 = 0x3C6EF372FE94F82B
	H3 = 0xA54FF53A5F1D36F1
	H4 = 0x510E527FADE682D1
	H5 = 0x9B05688C2B3E6C1F
	H6 = 0x1F83D9ABFB41BD6B
	H7 = 0x5BE0CD19137E2179

	# 定义K表：前80个素数2...409的立方根的小数部分的前64位
	K_table = (
		0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
		0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
		0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
		0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
		0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
		0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
		0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
		0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
		0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
		0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
		0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
		0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
		0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
		0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
		0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
		0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
		0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
		0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
		0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
		0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
	)

	# 将一个64位整数向右逐位旋转（64位循环右移）
	rotate_right = lambda x, n: (x >> n) | (x << (64 - n))

	# CH（choose）选择器
	CH = lambda x, y, z: (x & y) ^ (~x & z)

	# MAJ（majority）多数函数
	MAJ = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)

	# Σ₀
	BSIG0 = lambda x: rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39)

	# Σ₁
	BSIG1 = lambda x: rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41)

	# σ₀
	SSIG0 = lambda x: rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7)

	# σ₁
	SSIG1 = lambda x: rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6)

	# 对每一个1024位（128字节）的消息块进行循环
	for i in range(len(padded_data) // 128):
		# 消息扩展
		W_table = [0] * 80# 初始化W表

		# 将W表的前16个元素设置为消息块的内容（从0到15）
		for j in range(16):
			offset = i * 128 + j * 8

			W_table[j] = merge_int(padded_data[offset], padded_data[offset + 1], padded_data[offset + 2], padded_data[offset + 3], padded_data[offset + 4], padded_data[offset + 5], padded_data[offset + 6], padded_data[offset + 7])

		# 扩展W表（从16到79）
		for j in range(16, 80):
			W_table[j] = X64_add(X64_add(X64_add(SSIG1(W_table[j - 2]), W_table[j - 7]), SSIG0(W_table[j - 15])), W_table[j - 16])

		# 初始化工作变量：将H0...H7赋值给AA...HH
		AA = H0
		BB = H1
		CC = H2
		DD = H3
		EE = H4
		FF = H5
		GG = H6
		HH = H7

		# 80轮的主循环
		for rnd in range(80):
			# 计算临时变量
			T1 = X64_add(X64_add(X64_add(X64_add(HH, BSIG1(EE)), CH(EE, FF, GG)), K_table[rnd]), W_table[rnd])
			T2 = X64_add(BSIG0(AA), MAJ(AA, BB, CC))

			# 更新工作变量
			HH = GG
			GG = FF
			FF = EE
			EE = X64_add(DD, T1)
			DD = CC
			CC = BB
			BB = AA
			AA = X64_add(T1, T2)

		# 更新哈希值
		H0 = X64_add(AA, H0)
		H1 = X64_add(BB, H1)
		H2 = X64_add(CC, H2)
		H3 = X64_add(DD, H3)
		H4 = X64_add(EE, H4)
		H5 = X64_add(FF, H5)
		H6 = X64_add(GG, H6)
		H7 = X64_add(HH, H7)

	# 最终输出
	hashed = [H0, H1, H2, H3, H4, H5, H6, H7]
	final_output = []

	for i in range(0, len(hashed) * 64, 8):
		final_output.append((hashed[i >> 6] >> (56 - i % 64)) & 0xFF)

	return bytes(final_output)

# HMAC SHA-512
def HMAC_SHA512(input_data, key):
	# 初始化ipad和opad
	ipad = [0] * 128
	opad = [0] * 128

	# 密钥长度
	keyLen = len(key)

	# 密钥长度大于128字节，执行一次SHA512
	if keyLen > 128:
		key = SHA512(key)

	# 密钥长度不足128字节，填充n个0x00
	key += b"\x00" * (128 - keyLen)

	# 异或操作
	for i in range(128):
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C

	# 计算HMAC值
	return SHA512(bytes(opad) + SHA512(bytes(ipad) + input_data))


if __name__ == "__main__":
	input_data = "你好，世界".encode("utf-8")

	print(f"\n输入：{input_data.decode("utf-8")}")
	print(f"\nSHA-512值：{SHA512(input_data).hex()}")

	key = "114514".encode("utf-8")

	print(f"\n密钥：{key.decode("utf-8")}")
	print(f"\nHMAC SHA-512值：{HMAC_SHA512(input_data, key).hex()}\n")

"""
SHA512(<原始消息：字节>)
HMAC_SHA512(<原始消息：字节>, <密钥：字节>)
"""