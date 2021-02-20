package aes

import (
	"bytes"
	"testing"
)

var expandKeyTests = []struct {
	key []byte
	enc [][]uint32
	dec [][]uint32
}{
	{
		// A.1.  Expansion of a 128-bit Cipher Key
		[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		[][]uint32{
			{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c},
			{0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605},
			{0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f},
			{0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b},
			{0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00},
			{0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc},
			{0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd},
			{0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f},
			{0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f},
			{0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e},
			{0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6},
		},
		[][]uint32{
			{0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6},
			{0xc7b5a63, 0x1319eafe, 0xb0398890, 0x664cfbb4},
			{0xdf7d925a, 0x1f62b09d, 0xa320626e, 0xd6757324},
			{0x12c07647, 0xc01f22c7, 0xbc42d2f3, 0x7555114a},
			{0x6efcd876, 0xd2df5480, 0x7c5df034, 0xc917c3b9},
			{0x6ea30afc, 0xbc238cf6, 0xae82a4b4, 0xb54a338d},
			{0x90884413, 0xd280860a, 0x12a12842, 0x1bc89739},
			{0x7c1f13f7, 0x4208c219, 0xc021ae48, 0x969bf7b},
			{0xcc7505eb, 0x3e17d1ee, 0x82296c51, 0xc9481133},
			{0x2b3708a7, 0xf262d405, 0xbc3ebdbf, 0x4b617d62},
			{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x9cf4f3c},
		}},
	{
		// A.2.  Expansion of a 192-bit Cipher Key
		[]byte{
			0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
			0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
		},
		[][]uint32{
			{0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5},
			{0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5},
			{0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2},
			{0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd},
			{0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f},
			{0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6},
			{0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767},
			{0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971},
			{0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3},
			{0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e},
			{0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753},
			{0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5},
			{0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202},
		},
		nil},
	{
		// A.3.  Expansion of a 256-bit Cipher Key
		[]byte{
			0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
			0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
		},
		[][]uint32{
			{0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781},
			{0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4},
			{0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde},
			{0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a},
			{0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96},
			{0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3},
			{0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464},
			{0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214},
			{0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80},
			{0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239},
			{0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15},
			{0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3},
			{0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a},
			{0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d},
			{0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e},
		},
		nil},
}

func Test_expandKey(t *testing.T) {
	for i, tt := range expandKeyTests {
		enc := make([][]uint32, len(tt.enc))
		for j := 0; j < len(enc); j++ {
			enc[j] = make([]uint32, 4)
		}
		var dec [][]uint32
		if tt.dec != nil {
			dec = make([][]uint32, len(tt.dec))
			for j := 0; j < len(dec); j++ {
				dec[j] = make([]uint32, 4)
			}
		}
		expandKey(tt.key, enc, dec)
		for j, v := range enc {
			for k, u := range v {
				if u != tt.enc[j][k] {
					t.Errorf("key %d: enc[%d][%d] = %#x, want %#x", i, j, k, u, tt.enc[j][k])
				}
			}
		}
		for j, v := range dec {
			for k, u := range v {
				if u != tt.dec[j][k] {
					t.Errorf("key %d: dec[%d][%d] = %#x, want %#x", i, j, k, u, tt.dec[j][k])
				}
			}
		}
	}
}

var aesCipherTests = []struct {
	key []byte
	dec []byte
	enc []byte
}{
	{
		// Appendix B.
		[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		[]byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34},
		[]byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32}},
	{
		// Appendix C.1.  AES-128
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}},
	{
		// Appendix C.2.  AES-192
		[]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91}},
	{
		// Appendix C.3.  AES-256
		[]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89}},
}

func Test_aesCipher_Encrypt(t *testing.T) {
	for i, tt := range aesCipherTests {
		c, _ := NewCipher(tt.key)
		got := make([]byte, len(tt.enc))
		c.Encrypt(got, tt.dec)
		if !bytes.Equal(got, tt.enc) {
			t.Errorf("#%d: aesCipher.Encrypt() = %032x, want %032x", i, got, tt.enc)
		}
	}
}

func Test_aesCipher_Decrypt(t *testing.T) {
	for i, tt := range aesCipherTests {
		c, _ := NewCipher(tt.key)
		got := make([]byte, len(tt.dec))
		c.Decrypt(got, tt.enc)
		if !bytes.Equal(got, tt.dec) {
			t.Errorf("#%d: aesCipher.Decrypt() = %032x, want %032x", i, got, tt.dec)
		}
	}
}
