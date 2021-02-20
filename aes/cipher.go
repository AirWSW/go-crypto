// Advanced Encryption Standard - Wikipedia
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

package aes

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const BlockSize = 16

type aesCipher struct {
	enc [][]uint32
	dec [][]uint32
}

func NewCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	default:
		return nil, fmt.Errorf("invalid key size")
	case 16, 24, 32:
		break
	}
	l := len(key)/4 + 7
	c := new(aesCipher)
	c.enc = make([][]uint32, l)
	c.dec = make([][]uint32, l)
	for i := 0; i < l; i++ {
		c.enc[i] = make([]uint32, 4)
		c.dec[i] = make([]uint32, 4)
	}
	expandKey(key, c.enc, c.dec)
	return c, nil
}

func (c *aesCipher) BlockSize() int { return BlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	_, _ = dst[15], src[15] // early bounds check
	b := make([]uint32, 4)
	b[0] = binary.BigEndian.Uint32(src[0:4])
	b[1] = binary.BigEndian.Uint32(src[4:8])
	b[2] = binary.BigEndian.Uint32(src[8:12])
	b[3] = binary.BigEndian.Uint32(src[12:16])
	b = encryptBlock(c.enc, b)
	binary.BigEndian.PutUint32(dst[0:4], b[0])
	binary.BigEndian.PutUint32(dst[4:8], b[1])
	binary.BigEndian.PutUint32(dst[8:12], b[2])
	binary.BigEndian.PutUint32(dst[12:16], b[3])
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	_, _ = dst[15], src[15] // early bounds check
	b := make([]uint32, 4)
	b[0] = binary.BigEndian.Uint32(src[0:4])
	b[1] = binary.BigEndian.Uint32(src[4:8])
	b[2] = binary.BigEndian.Uint32(src[8:12])
	b[3] = binary.BigEndian.Uint32(src[12:16])
	b = decryptBlock(c.dec, b)
	binary.BigEndian.PutUint32(dst[0:4], b[0])
	binary.BigEndian.PutUint32(dst[4:8], b[1])
	binary.BigEndian.PutUint32(dst[8:12], b[2])
	binary.BigEndian.PutUint32(dst[12:16], b[3])
}

var sBox = [256]uint8{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

func encryptBlock(xk [][]uint32, b []uint32) []uint32 {
	l := len(xk)

	t0 := b[0] ^ xk[0][0]
	t1 := b[1] ^ xk[0][1]
	t2 := b[2] ^ xk[0][2]
	t3 := b[3] ^ xk[0][3]

	for i := 1; i < l-1; i++ {
		b[0] = uint32(sBox[t0>>24])<<24 | uint32(sBox[t0>>16&0xff])<<16 | uint32(sBox[t0>>8&0xff])<<8 | uint32(sBox[t0&0xff])
		b[1] = uint32(sBox[t1>>24])<<24 | uint32(sBox[t1>>16&0xff])<<16 | uint32(sBox[t1>>8&0xff])<<8 | uint32(sBox[t1&0xff])
		b[2] = uint32(sBox[t2>>24])<<24 | uint32(sBox[t2>>16&0xff])<<16 | uint32(sBox[t2>>8&0xff])<<8 | uint32(sBox[t2&0xff])
		b[3] = uint32(sBox[t3>>24])<<24 | uint32(sBox[t3>>16&0xff])<<16 | uint32(sBox[t3>>8&0xff])<<8 | uint32(sBox[t3&0xff])

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		b[0] = t0&0xff000000 | t1&0xff0000 | t2&0xff00 | t3&0xff
		b[1] = t1&0xff000000 | t2&0xff0000 | t3&0xff00 | t0&0xff
		b[2] = t2&0xff000000 | t3&0xff0000 | t0&0xff00 | t1&0xff
		b[3] = t3&0xff000000 | t0&0xff0000 | t1&0xff00 | t2&0xff

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		// Rijndael MixColumns
		// https://en.wikipedia.org/wiki/Rijndael_MixColumns
		b[0] = uint32(gmul(0x02, uint8(t0>>24))^gmul(0x03, uint8(t0>>16))^uint8(t0>>8)^uint8(t0))<<24 |
			uint32(uint8(t0>>24)^gmul(0x02, uint8(t0>>16))^gmul(0x03, uint8(t0>>8))^uint8(t0))<<16 |
			uint32(uint8(t0>>24)^uint8(t0>>16)^gmul(0x02, uint8(t0>>8))^gmul(0x03, uint8(t0)))<<8 |
			uint32(gmul(0x03, uint8(t0>>24))^uint8(t0>>16)^uint8(t0>>8)^gmul(0x02, uint8(t0)))
		b[1] = uint32(gmul(0x02, uint8(t1>>24))^gmul(0x03, uint8(t1>>16))^uint8(t1>>8)^uint8(t1))<<24 |
			uint32(uint8(t1>>24)^gmul(0x02, uint8(t1>>16))^gmul(0x03, uint8(t1>>8))^uint8(t1))<<16 |
			uint32(uint8(t1>>24)^uint8(t1>>16)^gmul(0x02, uint8(t1>>8))^gmul(0x03, uint8(t1)))<<8 |
			uint32(gmul(0x03, uint8(t1>>24))^uint8(t1>>16)^uint8(t1>>8)^gmul(0x02, uint8(t1)))
		b[2] = uint32(gmul(0x02, uint8(t2>>24))^gmul(0x03, uint8(t2>>16))^uint8(t2>>8)^uint8(t2))<<24 |
			uint32(uint8(t2>>24)^gmul(0x02, uint8(t2>>16))^gmul(0x03, uint8(t2>>8))^uint8(t2))<<16 |
			uint32(uint8(t2>>24)^uint8(t2>>16)^gmul(0x02, uint8(t2>>8))^gmul(0x03, uint8(t2)))<<8 |
			uint32(gmul(0x03, uint8(t2>>24))^uint8(t2>>16)^uint8(t2>>8)^gmul(0x02, uint8(t2)))
		b[3] = uint32(gmul(0x02, uint8(t3>>24))^gmul(0x03, uint8(t3>>16))^uint8(t3>>8)^uint8(t3))<<24 |
			uint32(uint8(t3>>24)^gmul(0x02, uint8(t3>>16))^gmul(0x03, uint8(t3>>8))^uint8(t3))<<16 |
			uint32(uint8(t3>>24)^uint8(t3>>16)^gmul(0x02, uint8(t3>>8))^gmul(0x03, uint8(t3)))<<8 |
			uint32(gmul(0x03, uint8(t3>>24))^uint8(t3>>16)^uint8(t3>>8)^gmul(0x02, uint8(t3)))

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		t0 ^= xk[i][0]
		t1 ^= xk[i][1]
		t2 ^= xk[i][2]
		t3 ^= xk[i][3]
	}

	b[0] = uint32(sBox[t0>>24])<<24 | uint32(sBox[t0>>16&0xff])<<16 | uint32(sBox[t0>>8&0xff])<<8 | uint32(sBox[t0&0xff])
	b[1] = uint32(sBox[t1>>24])<<24 | uint32(sBox[t1>>16&0xff])<<16 | uint32(sBox[t1>>8&0xff])<<8 | uint32(sBox[t1&0xff])
	b[2] = uint32(sBox[t2>>24])<<24 | uint32(sBox[t2>>16&0xff])<<16 | uint32(sBox[t2>>8&0xff])<<8 | uint32(sBox[t2&0xff])
	b[3] = uint32(sBox[t3>>24])<<24 | uint32(sBox[t3>>16&0xff])<<16 | uint32(sBox[t3>>8&0xff])<<8 | uint32(sBox[t3&0xff])

	t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

	b[0] = t0&0xff000000 | t1&0xff0000 | t2&0xff00 | t3&0xff
	b[1] = t1&0xff000000 | t2&0xff0000 | t3&0xff00 | t0&0xff
	b[2] = t2&0xff000000 | t3&0xff0000 | t0&0xff00 | t1&0xff
	b[3] = t3&0xff000000 | t0&0xff0000 | t1&0xff00 | t2&0xff

	b[0] ^= xk[l-1][0]
	b[1] ^= xk[l-1][1]
	b[2] ^= xk[l-1][2]
	b[3] ^= xk[l-1][3]

	return b
}

var inverseSBox = [256]uint8{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

func decryptBlock(xk [][]uint32, b []uint32) []uint32 {
	l := len(xk)

	t0 := b[0] ^ xk[0][0]
	t1 := b[1] ^ xk[0][1]
	t2 := b[2] ^ xk[0][2]
	t3 := b[3] ^ xk[0][3]

	for i := 1; i < l-1; i++ {
		b[0] = uint32(inverseSBox[t0>>24])<<24 | uint32(inverseSBox[t0>>16&0xff])<<16 | uint32(inverseSBox[t0>>8&0xff])<<8 | uint32(inverseSBox[t0&0xff])
		b[1] = uint32(inverseSBox[t1>>24])<<24 | uint32(inverseSBox[t1>>16&0xff])<<16 | uint32(inverseSBox[t1>>8&0xff])<<8 | uint32(inverseSBox[t1&0xff])
		b[2] = uint32(inverseSBox[t2>>24])<<24 | uint32(inverseSBox[t2>>16&0xff])<<16 | uint32(inverseSBox[t2>>8&0xff])<<8 | uint32(inverseSBox[t2&0xff])
		b[3] = uint32(inverseSBox[t3>>24])<<24 | uint32(inverseSBox[t3>>16&0xff])<<16 | uint32(inverseSBox[t3>>8&0xff])<<8 | uint32(inverseSBox[t3&0xff])

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		b[0] = t0&0xff000000 | t3&0xff0000 | t2&0xff00 | t1&0xff
		b[1] = t1&0xff000000 | t0&0xff0000 | t3&0xff00 | t2&0xff
		b[2] = t2&0xff000000 | t1&0xff0000 | t0&0xff00 | t3&0xff
		b[3] = t3&0xff000000 | t2&0xff0000 | t1&0xff00 | t0&0xff

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		// Rijndael MixColumns
		// https://en.wikipedia.org/wiki/Rijndael_MixColumns
		b[0] = uint32(gmul(14, uint8(t0>>24))^gmul(11, uint8(t0>>16))^gmul(13, uint8(t0>>8))^gmul(9, uint8(t0)))<<24 |
			uint32(gmul(9, uint8(t0>>24))^gmul(14, uint8(t0>>16))^gmul(11, uint8(t0>>8))^gmul(13, uint8(t0)))<<16 |
			uint32(gmul(13, uint8(t0>>24))^gmul(9, uint8(t0>>16))^gmul(14, uint8(t0>>8))^gmul(11, uint8(t0)))<<8 |
			uint32(gmul(11, uint8(t0>>24))^gmul(13, uint8(t0>>16))^gmul(9, uint8(t0>>8))^gmul(14, uint8(t0)))
		b[1] = uint32(gmul(14, uint8(t1>>24))^gmul(11, uint8(t1>>16))^gmul(13, uint8(t1>>8))^gmul(9, uint8(t1)))<<24 |
			uint32(gmul(9, uint8(t1>>24))^gmul(14, uint8(t1>>16))^gmul(11, uint8(t1>>8))^gmul(13, uint8(t1)))<<16 |
			uint32(gmul(13, uint8(t1>>24))^gmul(9, uint8(t1>>16))^gmul(14, uint8(t1>>8))^gmul(11, uint8(t1)))<<8 |
			uint32(gmul(11, uint8(t1>>24))^gmul(13, uint8(t1>>16))^gmul(9, uint8(t1>>8))^gmul(14, uint8(t1)))
		b[2] = uint32(gmul(14, uint8(t2>>24))^gmul(11, uint8(t2>>16))^gmul(13, uint8(t2>>8))^gmul(9, uint8(t2)))<<24 |
			uint32(gmul(9, uint8(t2>>24))^gmul(14, uint8(t2>>16))^gmul(11, uint8(t2>>8))^gmul(13, uint8(t2)))<<16 |
			uint32(gmul(13, uint8(t2>>24))^gmul(9, uint8(t2>>16))^gmul(14, uint8(t2>>8))^gmul(11, uint8(t2)))<<8 |
			uint32(gmul(11, uint8(t2>>24))^gmul(13, uint8(t2>>16))^gmul(9, uint8(t2>>8))^gmul(14, uint8(t2)))
		b[3] = uint32(gmul(14, uint8(t3>>24))^gmul(11, uint8(t3>>16))^gmul(13, uint8(t3>>8))^gmul(9, uint8(t3)))<<24 |
			uint32(gmul(9, uint8(t3>>24))^gmul(14, uint8(t3>>16))^gmul(11, uint8(t3>>8))^gmul(13, uint8(t3)))<<16 |
			uint32(gmul(13, uint8(t3>>24))^gmul(9, uint8(t3>>16))^gmul(14, uint8(t3>>8))^gmul(11, uint8(t3)))<<8 |
			uint32(gmul(11, uint8(t3>>24))^gmul(13, uint8(t3>>16))^gmul(9, uint8(t3>>8))^gmul(14, uint8(t3)))

		t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

		t0 ^= xk[i][0]
		t1 ^= xk[i][1]
		t2 ^= xk[i][2]
		t3 ^= xk[i][3]
	}

	b[0] = uint32(inverseSBox[t0>>24])<<24 | uint32(inverseSBox[t0>>16&0xff])<<16 | uint32(inverseSBox[t0>>8&0xff])<<8 | uint32(inverseSBox[t0&0xff])
	b[1] = uint32(inverseSBox[t1>>24])<<24 | uint32(inverseSBox[t1>>16&0xff])<<16 | uint32(inverseSBox[t1>>8&0xff])<<8 | uint32(inverseSBox[t1&0xff])
	b[2] = uint32(inverseSBox[t2>>24])<<24 | uint32(inverseSBox[t2>>16&0xff])<<16 | uint32(inverseSBox[t2>>8&0xff])<<8 | uint32(inverseSBox[t2&0xff])
	b[3] = uint32(inverseSBox[t3>>24])<<24 | uint32(inverseSBox[t3>>16&0xff])<<16 | uint32(inverseSBox[t3>>8&0xff])<<8 | uint32(inverseSBox[t3&0xff])

	t0, t1, t2, t3 = b[0], b[1], b[2], b[3]

	b[0] = t0&0xff000000 | t3&0xff0000 | t2&0xff00 | t1&0xff
	b[1] = t1&0xff000000 | t0&0xff0000 | t3&0xff00 | t2&0xff
	b[2] = t2&0xff000000 | t1&0xff0000 | t0&0xff00 | t3&0xff
	b[3] = t3&0xff000000 | t2&0xff0000 | t1&0xff00 | t0&0xff

	b[0] ^= xk[l-1][0]
	b[1] ^= xk[l-1][1]
	b[2] ^= xk[l-1][2]
	b[3] ^= xk[l-1][3]

	return b
}

// Rijndael MixColumns
// https://en.wikipedia.org/wiki/Rijndael_MixColumns
func gmul(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		if (b & 0x01) != 0 {
			p ^= a
		}
		if (a & 0x80) != 0 {
			a <<= 1
			a ^= 0x1b
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return p
}

var rcon = [16]byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
}

func expandKey(key []byte, enc, dec [][]uint32) {
	nk := len(key) / 4
	for i := 0; i < nk; i++ {
		enc[i/4][i%4] = binary.BigEndian.Uint32(key[4*i:])
	}
	for i := nk; i < len(enc)*4; i++ {
		g := enc[(i-1)/4][(i-1)%4]
		if i%nk == 0 {
			g = g<<8 | g>>24
		}
		if i%nk == 0 || (nk > 6 && i%nk == 4) {
			g = uint32(sBox[g>>24])<<24 | uint32(sBox[g>>16&0xff])<<16 | uint32(sBox[g>>8&0xff])<<8 | uint32(sBox[g&0xff])
		}
		if i%nk == 0 {
			g ^= uint32(rcon[i/nk-1]) << 24
		}
		enc[i/4][i%4] = enc[(i-nk)/4][(i-nk)%4] ^ g
	}

	if dec == nil {
		return
	}
	n := len(enc)
	for i := 0; i < n; i++ {
		for j := 0; j < 4; j++ {
			t := enc[n-i-1][j]
			if i > 0 && i < n-1 {
				t = uint32(gmul(14, uint8(t>>24))^gmul(11, uint8(t>>16))^gmul(13, uint8(t>>8))^gmul(9, uint8(t)))<<24 |
					uint32(gmul(9, uint8(t>>24))^gmul(14, uint8(t>>16))^gmul(11, uint8(t>>8))^gmul(13, uint8(t)))<<16 |
					uint32(gmul(13, uint8(t>>24))^gmul(9, uint8(t>>16))^gmul(14, uint8(t>>8))^gmul(11, uint8(t)))<<8 |
					uint32(gmul(11, uint8(t>>24))^gmul(13, uint8(t>>16))^gmul(9, uint8(t>>8))^gmul(14, uint8(t)))
			}
			dec[i][j] = t
		}
	}
}
