package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// MD5Hex 返回 data 的 md5 十六进制小写串。FingerprintHub 的 favicon 规则用此格式。
func MD5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// MMH3 计算 MurmurHash3 x86_32（seed=0），返回有符号 int32，
// 与 Python mmh3.hash() 及 nuclei favicon 的 mmh3 写法一致。
func MMH3(data []byte) int32 { return MMH3Seed(data, 0) }

// MMH3Seed 为指定种子的 MurmurHash3 x86_32。
func MMH3Seed(data []byte, seed uint32) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data)
	blocks := n / 4

	for i := 0; i < blocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}

	var k uint32
	switch tail := data[blocks*4:]; len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}

	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// MMH3Hex 返回 mmh3 的十六进制形式（有符号，如 -95a3ee0）。
func MMH3Hex(data []byte) string { return strconv.FormatInt(int64(MMH3(data)), 16) }

// MMH3HexUnsigned 返回 mmh3 的无符号 32 位十六进制形式（如 f6a5c120）。
func MMH3HexUnsigned(data []byte) string { return strconv.FormatUint(uint64(uint32(MMH3(data))), 16) }

// FaviconMatches 判断 favicon 原始字节是否命中哈希列表。
// 同时支持 md5（32 位十六进制）与 mmh3（十进制整数或十六进制）两种写法，
// 因为设计文档写的是 mmh3，而 FingerprintHub 上游实际使用 md5。
func FaviconMatches(hashes []string, icon []byte) bool {
	if len(hashes) == 0 || len(icon) == 0 {
		return false
	}
	var (
		md5Hex  string
		md5OK   bool
		dec     string
		hexSign string
		hexUn   string
		mmh3OK  bool
	)
	for _, h := range hashes {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if isDecimalHash(h) {
			if !mmh3OK {
				dec, hexSign, hexUn = mmh3Forms(icon)
				mmh3OK = true
			}
			if h == dec {
				return true
			}
			continue
		}
		// 十六进制写法：先按精确字符串比 md5，再比 mmh3 两种等价形式。
		if !md5OK {
			md5Hex = MD5Hex(icon)
			md5OK = true
		}
		norm := strings.TrimPrefix(strings.ToLower(h), "0x")
		if strings.EqualFold(norm, md5Hex) {
			return true
		}
		if !mmh3OK {
			dec, hexSign, hexUn = mmh3Forms(icon)
			mmh3OK = true
		}
		if norm == hexSign || norm == hexUn {
			return true
		}
	}
	return false
}

// mmh3Forms 返回同一 mmh3 值的三种常见写法。
func mmh3Forms(icon []byte) (dec, hexSigned, hexUnsigned string) {
	v := MMH3(icon)
	return strconv.FormatInt(int64(v), 10),
		strconv.FormatInt(int64(v), 16),
		strconv.FormatUint(uint64(uint32(v)), 16)
}

// isDecimalHash 判断是否是 mmh3 的十进制写法（可带负号）。
func isDecimalHash(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
