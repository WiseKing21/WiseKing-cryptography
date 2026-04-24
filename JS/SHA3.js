// 轮常量表：来自线性反馈移位寄存器
const rcon = [
	0x0000000000000001n, 0x0000000000008082n, 0x800000000000808An,
	0x8000000080008000n, 0x000000000000808Bn, 0x0000000080000001n,
	0x8000000080008081n, 0x8000000000008009n, 0x000000000000008An,
	0x0000000000000088n, 0x0000000080008009n, 0x000000008000000An,
	0x000000008000808Bn, 0x800000000000008Bn, 0x8000000000008089n,
	0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
	0x000000000000800An, 0x800000008000000An, 0x8000000080008081n,
	0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
]

// 旋转偏移量表
const ROTLTable = [
	[0n, 36n, 3n, 41n, 18n],
	[1n, 44n, 10n, 45n, 2n],
	[62n, 6n, 43n, 15n, 61n],
	[28n, 55n, 25n, 21n, 56n],
	[27n, 20n, 39n, 8n, 14n]
]

// Keccak F 置换函数
function KeccakF(state) {
	// 将一个64位整数向左逐位旋转（64位循环左移）
	const rotateLeft = (x, n) => ((x << n) | (x >> (64n - n))) & 0xFFFFFFFFFFFFFFFFn

	let CC = new Array(5)
	let DD = new Array(5)

	for (let rnd = 0; rnd < 24; rnd++) {
		// θ（theta）步骤：扩散
		for (let i = 0; i < 5; i++) {
			CC[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]
		}

		for (let i = 0; i < 5; i++) {
			DD[i] = CC[(i + 4) % 5] ^ rotateLeft(CC[(i + 1) % 5], 1n)

			for (let j = 0; j < 5; j++) {
				state[i + 5 * j] ^= DD[i]
			}
		}

		// ρ（rho）和π（pi）步骤：分别是循环左移和重新排列
		let BB = new Array(25)

		for (let i = 0; i < 5; i++) {
			for (let j = 0; j < 5; j++) {
				BB[j + 5 * ((2 * i + 3 * j) % 5)] = rotateLeft(state[i + 5 * j], ROTLTable[i][j])
			}
		}

		// χ（chi）步骤：混淆
		for (let i = 0; i < 5; i++) {
			for (let j = 0; j < 5; j++) {
				state[i + 5 * j] = BB[i + 5 * j] ^ (~BB[(i + 1) % 5 + 5 * j] & BB[(i + 2) % 5 + 5 * j])
			}
		}

		// ι（iota）步骤：和轮常量异或
		state[0] ^= rcon[rnd]
	}
}

// 消息填充函数
function padData(inputData, bitRate, delimitedSuffix) {
	const datLen = inputData.length
	let q = (bitRate - (datLen * 8 % bitRate)) / 8

	if (q === 1) {q += bitRate / 8}

	let paddedData = []

	for (let j = 0; j < (datLen + q); j++) {paddedData.push(0x00)}

	for (let i = 0; i < datLen; i++) {paddedData[i] = inputData[i]}

	// 添加终止符
	paddedData[datLen] |= delimitedSuffix
	paddedData[paddedData.length - 1] |= 0x80

	return paddedData
}

// 吸收和挤压函数
function absorbAndSqueeze(inputData, dgstLen, bitRate, delimitedSuffix) {
	if (dgstLen % 8 !== 0) {throw new Error("digest length must be a multiple of 8")}

	/*
	辅助函数：将8个8位整数合并为一个64位整数（小端序）
	例：[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0x0F] → 0x0FDEBC9A78563412n
	*/
	const mergeInt = (bArr) => BigInt(bArr[0]) | (BigInt(bArr[1]) << 8n) | (BigInt(bArr[2]) << 16n) | (BigInt(bArr[3]) << 24n) | (BigInt(bArr[4]) << 32n) | (BigInt(bArr[5]) << 40n) | (BigInt(bArr[6]) << 48n) | (BigInt(bArr[7]) << 56n)

	// 字节率
	const byteRate = bitRate / 8

	// 填充的原始消息
	const paddedData = padData(inputData, bitRate, delimitedSuffix)

	// 初始化状态矩阵
	let state = [
		0n, 0n, 0n, 0n, 0n,
		0n, 0n, 0n, 0n, 0n,
		0n, 0n, 0n, 0n, 0n,
		0n, 0n, 0n, 0n, 0n,
		0n, 0n, 0n, 0n, 0n
	]

	// 矩阵中的每一个元素都是64位（小端序），大小为1600位（200字节）

	// 吸收阶段
	for (let offset = 0; offset < paddedData.length; offset += byteRate) {
		const block = paddedData.slice(offset, offset + byteRate)

		for (let i = 0; i < (block.length / 8); i++) {
			state[i] ^= mergeInt(block.slice(i * 8, (i + 1) * 8))
		}

		KeccakF(state)
	}

	// 挤压阶段
	let finalOutput = []

	for (let i = 0; i < state.length * 64; i += 8) {
		finalOutput.push(Number.parseInt((state[i >> 6] >> BigInt(i % 64)) & 0xFFn))
	}

	// 最终输出
	return finalOutput.slice(0, dgstLen / 8)
}

// SHA3
function SHA3(inputData, dgstLen) {
	if (![224, 256, 384, 512].includes(dgstLen)) {throw new Error("digest length must be 224, 256, 384, 512 bits")}

	return absorbAndSqueeze(inputData, dgstLen, 1600 - (dgstLen * 2), 0x06)
}

// SHAKE128
const SHAKE128 = (inputData, dgstLen) => absorbAndSqueeze(inputData, dgstLen, 1344, 0x1F)

// SHAKE256
const SHAKE256 = (inputData, dgstLen) => absorbAndSqueeze(inputData, dgstLen, 1088, 0x1F)

// HMAC SHA3
function HMAC_SHA3(inputData, key, dgstLen) {
	if (![224, 256, 384, 512].includes(dgstLen)) {throw new Error("digest length must be 224, 256, 384, 512 bits")}

	// SHA3的分组长度的选择（字节）
	let blockSize = 0

	switch (dgstLen) {
		case 224:
			blockSize = 144
			break
		case 256:
			blockSize = 136
			break
		case 384:
			blockSize = 104
			break
		case 512:
			blockSize = 72
			break
	}

	// 初始化ipad和opad
	let ipad = new Array(blockSize)
	let opad = new Array(blockSize)

	// 密钥长度
	const keyLen = key.length

	// 密钥长度大于SHA3的分组长度，执行一次SHA3
	if (keyLen > blockSize) {key = SHA3(key, dgstLen)}

	// 密钥长度不足SHA3的分组长度，填充n个0x00
	for (let j = 0; j < (keyLen - blockSize); j++) {key.push(0x00)}

	// 异或操作
	for (let i = 0; i < blockSize; i++) {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5C
	}

	// 计算HMAC值
	return SHA3(opad.concat(SHA3(ipad.concat(inputData), dgstLen)), dgstLen)
}

/*
SHA3：

SHA3(<原始消息：字节数组>, <摘要长度：正整数>)
HMAC_SHA3(<原始消息：字节数组>, <密钥：字节数组>, <摘要长度：正整数>)

SHA3的摘要长度必须为224、256、384、512位




SHAKE128、SHAKE256：

SHAKE128(<原始消息：字节>, <摘要长度：正整数>)
SHAKE256(<原始消息：字节>, <摘要长度：正整数>)

SHAKE128、SHAKE256的摘要长度必须为8的倍数
SHAKE128、SHAKE256不支持HMAC
*/