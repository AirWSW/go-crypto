// FIPS 46-3: Data Encryption Standard (DES)
// https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25

// Data Encryption Standard - Wikipedia
// https://en.wikipedia.org/wiki/Data_Encryption_Standard

// The DES Algorithm Illustrated - by J. Orlin Grabbe
// http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

package des

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const BlockSize = 8

type desCipher struct {
	subKeys []uint64
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("invalid key size")
	}
	c := new(desCipher)
	c.subKeys = newSubKeys(binary.BigEndian.Uint64(key))
	return c, nil
}

func (c *desCipher) BlockSize() int { return BlockSize }

func (c *desCipher) Encrypt(dst, src []byte) {
	_, _ = dst[7], src[7] // early bounds check
	binary.BigEndian.PutUint64(dst[:8], encryptBlock(c.subKeys[:], binary.BigEndian.Uint64(src[:8])))
}

func (c *desCipher) Decrypt(dst, src []byte) {
	_, _ = dst[7], src[7] // early bounds check
	binary.BigEndian.PutUint64(dst[:8], decryptBlock(c.subKeys[:], binary.BigEndian.Uint64(src[:8])))
}

func encryptBlock(subKeys []uint64, b uint64) uint64 {
	return cryptBlock(subKeys, b)
}

func decryptBlock(subKeys []uint64, b uint64) uint64 {
	tk := make([]uint64, 0, len(subKeys))
	for i := len(subKeys) - 1; i >= 0; i-- {
		tk = append(tk, subKeys[i])
	}
	return cryptBlock(tk, b)
}

var initialPermutation = [64]uint8{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var finalPermutation = [64]uint8{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

func cryptBlock(subKeys []uint64, b uint64) uint64 {
	b = permute(b, initialPermutation[:], 64)
	l, r := uint32(b>>32), uint32(b)
	for _, k := range subKeys {
		l, r = feistel(l, r, k)
	}
	b = (uint64(r) << 32) | uint64(l)
	b = permute(b, finalPermutation[:], 64)
	return b
}

var expansionFunction = [48]uint8{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var sBoxes = [8][4][16]uint8{
	// S-box 1
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	// S-box 2
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	// S-box 3
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	// S-box 4
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	// S-box 5
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	// S-box 6
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	// S-box 7
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	// S-box 8
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

var permutationFunction = [32]uint8{
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25,
}

func feistel(l, r uint32, k uint64) (uint32, uint32) {
	k ^= permute(uint64(r), expansionFunction[:], 32)
	s := uint32(0)
	for i, sbox := range sBoxes {
		i = 7 - i
		r, c := (k>>(i*6))&0x1|(k>>(4+i*6))&0x2, (k>>(1+i*6))&0xf
		s |= uint32(sbox[r][c]) << (i * 4)
	}
	l ^= uint32(permute(uint64(s), permutationFunction[:], 32))
	return r, l
}

var permutedChoice1 = [56]uint8{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var permutedChoice2 = [48]uint8{
	14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32,
}

var leftRotations = []uint8{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
}

func newSubKeys(k uint64) []uint64 {
	k = permute(k, permutedChoice1[:], 64)
	l, r := uint32(k>>28), uint32(k&0xfffffff)
	subKeys := make([]uint64, 16)
	for i, n := range leftRotations {
		l, r = (l<<n|l>>(28-n))&0xfffffff, (r<<n|r>>(28-n))&0xfffffff
		k = uint64(l)<<28 | uint64(r)
		subKeys[i] = permute(k, permutedChoice2[:], 56)
	}
	return subKeys
}

func permute(b uint64, p []uint8, l uint8) uint64 {
	u := uint64(1 << (len(p) - 1))
	v := uint64(1 << (l - 1))
	t := uint64(0)
	for i, n := range p {
		if (v>>(n-1))&b != 0 {
			t |= u >> i
		}
	}
	return t
}

type tripleDESCipher struct {
	cipher1, cipher2, cipher3 *desCipher
}

// NewTripleDESCipher creates and returns a new cipher.Block.
func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, fmt.Errorf("short key")
	}
	c := new(tripleDESCipher)
	c.cipher1 = new(desCipher)
	c.cipher2 = new(desCipher)
	c.cipher3 = new(desCipher)
	c.cipher1.subKeys = newSubKeys(binary.BigEndian.Uint64(key[:8]))
	c.cipher2.subKeys = newSubKeys(binary.BigEndian.Uint64(key[8:16]))
	c.cipher3.subKeys = newSubKeys(binary.BigEndian.Uint64(key[16:]))
	return c, nil
}

func (c *tripleDESCipher) BlockSize() int { return BlockSize }

func (c *tripleDESCipher) Encrypt(dst, src []byte) {
	_, _ = dst[7], src[7] // early bounds check
	binary.BigEndian.PutUint64(dst[:8],
		encryptBlock(c.cipher3.subKeys[:],
			decryptBlock(c.cipher2.subKeys[:],
				encryptBlock(c.cipher1.subKeys[:], binary.BigEndian.Uint64(src[:8])))))
}

func (c *tripleDESCipher) Decrypt(dst, src []byte) {
	_, _ = dst[7], src[7] // early bounds check
	binary.BigEndian.PutUint64(dst[:8],
		decryptBlock(c.cipher1.subKeys[:],
			encryptBlock(c.cipher2.subKeys[:],
				decryptBlock(c.cipher3.subKeys[:], binary.BigEndian.Uint64(src[:8])))))
}
