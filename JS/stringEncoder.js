// 字符串转换为字节数组（UTF-8编码）
function encodeUTF8(str) {
	let bArr = []

	for (let i = 0; i < str.length; i++) {
		const p = str.charCodeAt(i)

		if (p <= 0x007F) {// U+0000...U+007F
			bArr.push(p)
		} else if ((p >= 0x0080) && (p <= 0x07FF)) {// U+0080...U+07FF
			bArr.push((p >> 6) | 0xC0)
			bArr.push((p & 0x3F) | 0x80)
		} else {// U+0800...U+FFFF
			bArr.push((p >> 12) | 0xE0)
			bArr.push(((p >> 6) & 0x3F) | 0x80)
			bArr.push((p & 0x3F) | 0x80)
		}
	}

	return bArr
}

// 字节数组转换为字符串（UTF-8解码）
function decodeUTF8(bArr) {
	let str = ""
	let i = 0
	let c2 = 0
	let c3 = 0
	let c4 = 0

	while (i < bArr.length) {
		const c1 = bArr[i]

		if (c1 <= 0x007F) {
			str += String.fromCharCode(c1)
			i++
		} else if ((c1 >= 0x00C0) && (c1 <= 0x00DF)) {
			c2 = bArr[i + 1]
			str += String.fromCharCode(((c1 & 0x1F) << 6) | (c2 & 0x3F))
			i += 2
		} else {
			c2 = bArr[i + 1]
			c3 = bArr[i + 2]
			str += String.fromCharCode(((c1 & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F))
			i += 3
		}
	}

	return str
}

// 字节数组转换为十六进制字符串
function byte2hex(bArr) {
	const hexTable = "0123456789abcdef"

	let hexStr = ""

	for (const b of bArr) {
		hexStr += hexTable[b >> 4 & 0x0F]// 高4位
		hexStr += hexTable[b & 0x0F]// 低4位
	}

	return hexStr
}

// 十六进制字符串转换为字节数组
function hex2byte(hexStr) {
	let bArr = []

	for (let i = 0; i < hexStr.length; i += 2) {
		bArr.push(Number.parseInt(hexStr.slice(i, i + 2), 16))
	}

	return bArr
}