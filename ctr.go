package main

import (
	"crypto/cipher"
)

type ctrStream struct {
	block   cipher.Block
	ctr     []byte
	out     []byte
	outUsed int
}

// NewCTR returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	if len(iv) != block.BlockSize() {
		panic("invalid IV length")
	}
	b := make([]byte, len(iv))
	copy(b, iv)
	bufSize := 512
	if bufSize < block.BlockSize() {
		bufSize = block.BlockSize()
	}
	return &ctrStream{
		block:   block,
		ctr:     b,
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
}

func (s *ctrStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	for len(src) > 0 {
		if s.outUsed >= len(s.out)-s.block.BlockSize() {
			s.refill()
		}
		n := xorBytes(dst, src, s.out[s.outUsed:])
		dst = dst[n:]
		src = src[n:]
		s.outUsed += n
	}
}

func (s *ctrStream) refill() {
	remain := len(s.out) - s.outUsed
	copy(s.out, s.out[s.outUsed:])
	s.out = s.out[:cap(s.out)]
	bs := s.block.BlockSize()
	for remain <= len(s.out)-bs {
		s.block.Encrypt(s.out[remain:], s.ctr)
		remain += bs

		// Increment counter
		for i := len(s.ctr) - 1; i >= 0; i-- {
			s.ctr[i]++
			if s.ctr[i] != 0 {
				break
			}
		}
	}
	s.out = s.out[:remain]
	s.outUsed = 0
}

func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
