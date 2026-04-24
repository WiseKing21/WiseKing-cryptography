function SHA512(inputData) {
	/*
	辅助函数：将两个32位整数合并为一个64位整数（大端序）
	例：0x12345678, 0x9ABCDE0F → 0x123456789ABCDE0Fn
	*/
	const mergeInt = (a, b) => (BigInt(a) << 32n) | BigInt(b)

	// 模2⁶⁴加法
	const X64Add = (a, b) => (a + b) & 0xFFFFFFFFFFFFFFFFn

	// 消息填充
	let paddedData = []

	// 消息长度（位）
	const datLen = inputData.length * 8

	// 将原始消息转换为32位字（word）
	for (let i = 0; i < datLen; i += 8) {
		paddedData[i >> 5] |= inputData[i / 8] << (24 - i % 32)
	}

	// 将消息长度附加到末尾（16字节大端序）
	paddedData[datLen >> 5] |= 0x80 << (24 - datLen % 32)
	paddedData[((datLen + 128 >> 10) << 5) + 31] = datLen

	// 定义初始哈希值：前8个素数2...19的平方根的小数部分的前64位
	let H0 = 0x6A09E667F3BCC908n
	let H1 = 0xBB67AE8584CAA73Bn
	let H2 = 0x3C6EF372FE94F82Bn
	let H3 = 0xA54FF53A5F1D36F1n
	let H4 = 0x510E527FADE682D1n
	let H5 = 0x9B05688C2B3E6C1Fn
	let H6 = 0x1F83D9ABFB41BD6Bn
	let H7 = 0x5BE0CD19137E2179n

	// 定义K表：前80个素数2...409的立方根的小数部分的前64位
	const KTable = [
		0x428A2F98D728AE22n, 0x7137449123EF65CDn, 0xB5C0FBCFEC4D3B2Fn, 0xE9B5DBA58189DBBCn,
		0x3956C25BF348B538n, 0x59F111F1B605D019n, 0x923F82A4AF194F9Bn, 0xAB1C5ED5DA6D8118n,
		0xD807AA98A3030242n, 0x12835B0145706FBEn, 0x243185BE4EE4B28Cn, 0x550C7DC3D5FFB4E2n,
		0x72BE5D74F27B896Fn, 0x80DEB1FE3B1696B1n, 0x9BDC06A725C71235n, 0xC19BF174CF692694n,
		0xE49B69C19EF14AD2n, 0xEFBE4786384F25E3n, 0x0FC19DC68B8CD5B5n, 0x240CA1CC77AC9C65n,
		0x2DE92C6F592B0275n, 0x4A7484AA6EA6E483n, 0x5CB0A9DCBD41FBD4n, 0x76F988DA831153B5n,
		0x983E5152EE66DFABn, 0xA831C66D2DB43210n, 0xB00327C898FB213Fn, 0xBF597FC7BEEF0EE4n,
		0xC6E00BF33DA88FC2n, 0xD5A79147930AA725n, 0x06CA6351E003826Fn, 0x142929670A0E6E70n,
		0x27B70A8546D22FFCn, 0x2E1B21385C26C926n, 0x4D2C6DFC5AC42AEDn, 0x53380D139D95B3DFn,
		0x650A73548BAF63DEn, 0x766A0ABB3C77B2A8n, 0x81C2C92E47EDAEE6n, 0x92722C851482353Bn,
		0xA2BFE8A14CF10364n, 0xA81A664BBC423001n, 0xC24B8B70D0F89791n, 0xC76C51A30654BE30n,
		0xD192E819D6EF5218n, 0xD69906245565A910n, 0xF40E35855771202An, 0x106AA07032BBD1B8n,
		0x19A4C116B8D2D0C8n, 0x1E376C085141AB53n, 0x2748774CDF8EEB99n, 0x34B0BCB5E19B48A8n,
		0x391C0CB3C5C95A63n, 0x4ED8AA4AE3418ACBn, 0x5B9CCA4F7763E373n, 0x682E6FF3D6B2B8A3n,
		0x748F82EE5DEFB2FCn, 0x78A5636F43172F60n, 0x84C87814A1F0AB72n, 0x8CC702081A6439ECn,
		0x90BEFFFA23631E28n, 0xA4506CEBDE82BDE9n, 0xBEF9A3F7B2C67915n, 0xC67178F2E372532Bn,
		0xCA273ECEEA26619Cn, 0xD186B8C721C0C207n, 0xEADA7DD6CDE0EB1En, 0xF57D4F7FEE6ED178n,
		0x06F067AA72176FBAn, 0x0A637DC5A2C898A6n, 0x113F9804BEF90DAEn, 0x1B710B35131C471Bn,
		0x28DB77F523047D84n, 0x32CAAB7B40C72493n, 0x3C9EBE0A15C9BEBCn, 0x431D67C49C100D4Cn,
		0x4CC5D4BECB3E42B6n, 0x597F299CFC657E2An, 0x5FCB6FAB3AD6FAECn, 0x6C44198C4A475817n
	]

	// 将一个64位整数向右逐位旋转（64位循环右移）
	const rotateRight = (x, n) => (x >> n) | (x << (64n - n))

	// CH（choose）选择器
	const CH = (x, y, z) => (x & y) ^ (~x & z)

	// MAJ（majority）多数函数
	const MAJ = (x, y, z) => (x & y) ^ (x & z) ^ (y & z)

	// Σ₀
	const BSIG0 = (x) => rotateRight(x, 28n) ^ rotateRight(x, 34n) ^ rotateRight(x, 39n)

	// Σ₁
	const BSIG1 = (x) => rotateRight(x, 14n) ^ rotateRight(x, 18n) ^ rotateRight(x, 41n)

	// σ₀
	const SSIG0 = (x) => rotateRight(x, 1n) ^ rotateRight(x, 8n) ^ (x >> 7n)

	// σ₁
	const SSIG1 = (x) => rotateRight(x, 19n) ^ rotateRight(x, 61n) ^ (x >> 6n)

	// 对每一个1024位（128字节）的消息块进行循环
	for (let i = 0; i < paddedData.length; i += 32) {
		// 消息扩展
		let WTable = new Array(80)// 初始化W表

		for (let j = 0; j < 16; j++) {// 将W表的前16个元素设置为消息块的内容（从0到15）
			WTable[j] = mergeInt(paddedData[i + 2 * j] >>> 0, paddedData[i + 2 * j + 1] >>> 0)
		}

		for (let j = 16; j < 80; j++) {// 扩展W表（从16到79）
			WTable[j] = X64Add(X64Add(X64Add(SSIG1(WTable[j - 2]), WTable[j - 7]), SSIG0(WTable[j - 15])), WTable[j - 16])
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

		// 80轮的主循环
		for (let rnd = 0; rnd < 80; rnd++) {
			// 计算临时变量
			const T1 = X64Add(X64Add(X64Add(X64Add(HH, BSIG1(EE)), CH(EE, FF, GG)), KTable[rnd]), WTable[rnd])
			const T2 = X64Add(BSIG0(AA), MAJ(AA, BB, CC))

			// 更新工作变量
			HH = GG
			GG = FF
			FF = EE
			EE = X64Add(DD, T1)
			DD = CC
			CC = BB
			BB = AA
			AA = X64Add(T1, T2)
		}

		// 更新哈希值
		H0 = X64Add(AA, H0)
		H1 = X64Add(BB, H1)
		H2 = X64Add(CC, H2)
		H3 = X64Add(DD, H3)
		H4 = X64Add(EE, H4)
		H5 = X64Add(FF, H5)
		H6 = X64Add(GG, H6)
		H7 = X64Add(HH, H7)
	}

	// 最终输出
	const hashed = [H0, H1, H2, H3, H4, H5, H6, H7]
	let finalOutput = []

	for (let i = 0; i < hashed.length * 64; i += 8) {
		finalOutput.push(Number.parseInt((hashed[i >> 6] >> BigInt(56 - i % 64)) & 0xFFn))
	}

	return finalOutput
}

// HMAC SHA-512
function HMAC_SHA512(inputData, key) {
	// 初始化ipad和opad
	let ipad = new Array(128)
	let opad = new Array(128)

	// 密钥长度
	const keyLen = key.length

	// 密钥长度大于128字节，执行一次SHA512
	if (keyLen > 128) {key = SHA512(key)}

	// 密钥长度不足128字节，填充n个0x00
	for (let j = 0; j < (128 - keyLen); j++) {key.push(0x00)}

	// 异或操作
	for (let i = 0; i < 128; i++) {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C
	}

	// 计算HMAC值
	return SHA512(opad.concat(SHA512(ipad.concat(inputData))))
}

/*
SHA512(<原始消息：字节数组>)
HMAC_SHA512(<原始消息：字节数组>, <密钥：字节数组>)
*/