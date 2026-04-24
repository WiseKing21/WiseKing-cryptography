// 模2³²加法
function X32Add(a, b) {
	const lsb = (a & 0xFFFF) + (b & 0xFFFF)

	return ((a >> 16) + (b >> 16) + (lsb >> 16) << 16) | (lsb & 0xFFFF)
}

// SHA-256主函数
function SHA256(inputData) {
	// 消息填充
	let paddedData = []

	// 消息长度（位）
	const datLen = inputData.length * 8

	// 将原始消息转换为32位字（word）
	for (let i = 0; i < datLen; i += 8) {
		paddedData[i >> 5] |= inputData[i / 8] << (24 - i % 32)
	}

	// 将消息长度附加到末尾（8字节大端序）
	paddedData[datLen >> 5] |= 0x80 << (24 - datLen % 32)
	paddedData[((datLen + 64 >> 9) << 4) + 15] = datLen

	// 定义初始哈希值：前8个素数2...19的平方根的小数部分的前32位
	let H0 = 0x6A09E667
	let H1 = 0xBB67AE85
	let H2 = 0x3C6EF372
	let H3 = 0xA54FF53A
	let H4 = 0x510E527F
	let H5 = 0x9B05688C
	let H6 = 0x1F83D9AB
	let H7 = 0x5BE0CD19

	// 定义K表：前64个素数2...311的立方根的小数部分的前32位
	const KTable = [
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	]

	// 将一个32位整数向右逐位旋转（32位循环右移）
	const rotateRight = (x, n) => (x >>> n) | (x << (32 - n))

	// CH（choose）选择器
	const CH = (x, y, z) => (x & y) ^ (~x & z)

	// MAJ（majority）多数函数
	const MAJ = (x, y, z) => (x & y) ^ (x & z) ^ (y & z)

	// Σ₀
	const BSIG0 = (x) => rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22)

	// Σ₁
	const BSIG1 = (x) => rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25)

	// σ₀
	const SSIG0 = (x) => rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3)

	// σ₁
	const SSIG1 = (x) => rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >>> 10)

	// 对每一个512位（64字节）的消息块进行循环
	for (let i = 0; i < paddedData.length; i += 16) {
		// 消息扩展
		let WTable = new Array(64)// 初始化W表

		for (let j = 0; j < 16; j++) {// 将W表的前16个元素设置为消息块的内容（从0到15）
			WTable[j] = paddedData[j + i]
		}

		for (let j = 16; j < 64; j++) {// 扩展W表（从16到63）
			WTable[j] = X32Add(X32Add(X32Add(SSIG1(WTable[j - 2]), WTable[j - 7]), SSIG0(WTable[j - 15])), WTable[j - 16])
		}

		// 初始化工作变量：将H0...H7赋值给AA...HH
		let AA = H0
		let BB = H1
		let CC = H2
		let DD = H3
		let EE = H4
		let FF = H5
		let GG = H6
		let HH = H7

		// 64轮的主循环
		for (let rnd = 0; rnd < 64; rnd++) {
			// 计算临时变量
			const T1 = X32Add(X32Add(X32Add(X32Add(HH, BSIG1(EE)), CH(EE, FF, GG)), KTable[rnd]), WTable[rnd])
			const T2 = X32Add(BSIG0(AA), MAJ(AA, BB, CC))

			// 更新工作变量
			HH = GG
			GG = FF
			FF = EE
			EE = X32Add(DD, T1)
			DD = CC
			CC = BB
			BB = AA
			AA = X32Add(T1, T2)
		}

		// 更新哈希值
		H0 = X32Add(AA, H0)
		H1 = X32Add(BB, H1)
		H2 = X32Add(CC, H2)
		H3 = X32Add(DD, H3)
		H4 = X32Add(EE, H4)
		H5 = X32Add(FF, H5)
		H6 = X32Add(GG, H6)
		H7 = X32Add(HH, H7)
	}

	// 最终输出
	const hashed = [H0, H1, H2, H3, H4, H5, H6, H7]
	let finalOutput = []

	for (let i = 0; i < hashed.length * 32; i += 8) {
		finalOutput.push((hashed[i >> 5] >>> (24 - i % 32)) & 0xFF)
	}

	return finalOutput
}

// HMAC SHA-256
function HMAC_SHA256(inputData, key) {
	// 初始化ipad和opad
	let ipad = new Array(64)
	let opad = new Array(64)

	// 密钥长度
	const keyLen = key.length

	// 密钥长度大于64字节，执行一次SHA256
	if (keyLen > 64) {key = SHA256(key)}

	// 密钥长度不足64字节，填充n个0x00
	for (let j = 0; j < (64 - keyLen); j++) {key.push(0x00)}

	// 异或操作
	for (let i = 0; i < 64; i++) {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C
	}

	// 计算HMAC值
	return SHA256(opad.concat(SHA256(ipad.concat(inputData))))
}

/*
SHA256(<原始消息：字节数组>)
HMAC_SHA256(<原始消息：字节数组>, <密钥：字节数组>)
*/