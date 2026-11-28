// SPDX-License-Identifier: GPL-2.0-or-later
//
// PBKDF2-HMAC-SHA256 for kernel use.
//
// The module is self-contained: it keeps its own SHA-256 rather than importing
// krandom, so it can be compiled on the host and checked against published
// vectors (tests/kdf), and so it needs no RNG initialisation. It allocates
// nothing: every workspace is a fixed stack array or borrowed from the caller.
module kdf

pub const digest_bytes = u64(32)
pub const block_bytes = u64(64)

struct Sha256 {
mut:
	state [8]u32
	block [64]u8
	used  u64
	total u64
}

fn rotr(value u32, shift u32) u32 {
	return (value >> shift) | (value << (32 - shift))
}

fn compress(mut s Sha256) {
	constants := [u32(0x428a2f98), 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]!
	mut words := [64]u32{}
	for i in 0 .. 16 {
		at := i * 4
		words[i] = u32(s.block[at]) << 24 | u32(s.block[at + 1]) << 16 |
			u32(s.block[at + 2]) << 8 | u32(s.block[at + 3])
	}
	for i in 16 .. 64 {
		left := words[i - 15]
		right := words[i - 2]
		lower := rotr(left, 7) ^ rotr(left, 18) ^ (left >> 3)
		upper := rotr(right, 17) ^ rotr(right, 19) ^ (right >> 10)
		words[i] = words[i - 16] + lower + words[i - 7] + upper
	}
	mut a := s.state[0]
	mut b := s.state[1]
	mut c := s.state[2]
	mut d := s.state[3]
	mut e := s.state[4]
	mut f := s.state[5]
	mut g := s.state[6]
	mut h := s.state[7]
	for i in 0 .. 64 {
		upper := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
		choose := (e & f) ^ (~e & g)
		first := h + upper + choose + constants[i] + words[i]
		lower := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
		majority := (a & b) ^ (a & c) ^ (b & c)
		second := lower + majority
		h = g
		g = f
		f = e
		e = d + first
		d = c
		c = b
		b = a
		a = first + second
	}
	s.state[0] += a
	s.state[1] += b
	s.state[2] += c
	s.state[3] += d
	s.state[4] += e
	s.state[5] += f
	s.state[6] += g
	s.state[7] += h
}

fn start(mut s Sha256) {
	s.state = [u32(0x6a09e667), 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]!
	s.used = 0
	s.total = 0
}

fn feed(mut s Sha256, data &u8, length u64) {
	s.total += length
	for i in u64(0) .. length {
		s.block[s.used] = unsafe { data[i] }
		s.used++
		if s.used == block_bytes {
			compress(mut s)
			s.used = 0
		}
	}
}

fn finish(mut s Sha256, out &[32]u8) {
	bits := s.total * 8
	s.block[s.used] = 0x80
	s.used++
	if s.used > 56 {
		for s.used < block_bytes {
			s.block[s.used] = 0
			s.used++
		}
		compress(mut s)
		s.used = 0
	}
	for s.used < 56 {
		s.block[s.used] = 0
		s.used++
	}
	for i in 0 .. 8 {
		s.block[56 + i] = u8(bits >> u64((7 - i) * 8))
	}
	compress(mut s)
	for i in 0 .. 8 {
		for byte in 0 .. 4 {
			unsafe {
				out[i * 4 + byte] = u8(s.state[i] >> u32(24 - byte * 8))
			}
		}
	}
}

fn sha256(data &u8, length u64, out &[32]u8) {
	mut s := Sha256{}
	start(mut s)
	feed(mut s, data, length)
	finish(mut s, out)
}

fn hmac_two(key &u8, key_len u64, first &u8, first_len u64, second &u8, second_len u64, out &[32]u8) {
	mut short := [32]u8{}
	if key_len > block_bytes {
		sha256(key, key_len, &short)
	}
	mut inner_key := [64]u8{}
	for i in u64(0) .. block_bytes {
		byte := if key_len > block_bytes {
			if i < digest_bytes {
				short[i]
			} else {
				u8(0)
			}
		} else if i < key_len {
			unsafe { key[i] }
		} else {
			u8(0)
		}
		inner_key[i] = byte ^ u8(0x36)
	}
	mut inner := Sha256{}
	start(mut inner)
	feed(mut inner, &inner_key[0], block_bytes)
	feed(mut inner, first, first_len)
	feed(mut inner, second, second_len)
	mut digest := [32]u8{}
	finish(mut inner, &digest)
	mut outer := Sha256{}
	start(mut outer)
	for i in 0 .. block_bytes {
		inner_key[i] ^= u8(0x36) ^ u8(0x5c)
	}
	feed(mut outer, &inner_key[0], block_bytes)
	feed(mut outer, &digest[0], digest_bytes)
	finish(mut outer, out)
}

// HMAC-SHA256 over one message. The key and the message are borrowed.
pub fn authenticate(key &u8, key_len u64, data &u8, data_len u64, out &[32]u8) {
	mut empty := [1]u8{}
	hmac_two(key, key_len, data, data_len, &empty[0], 0, out)
}

// PBKDF2-HMAC-SHA256. `workspace` is borrowed and must hold at least
// salt_len + 4 bytes; it is used for salt || the block counter. `output` is
// borrowed and must hold output_len bytes. iterations must be positive.
pub fn derive(password &u8, password_len u64, salt &u8, salt_len u64, iterations u64, output &u8, output_len u64, workspace &u8, workspace_bytes u64) bool {
	if iterations == 0 || output_len == 0 || output_len > u64(0xffffffff) * digest_bytes {
		return false
	}
	if workspace_bytes < salt_len + 4 {
		return false
	}
	for i in u64(0) .. salt_len {
		unsafe { workspace[i] = salt[i] }
	}
	mut empty := [1]u8{}
	blocks := (output_len + digest_bytes - 1) / digest_bytes
	for block := u64(1); block <= blocks; block++ {
		for i in 0 .. 4 {
			unsafe { workspace[salt_len + i] = u8(block >> u64((3 - i) * 8)) }
		}
		mut u := [32]u8{}
		mut t := [32]u8{}
		hmac_two(password, password_len, workspace, salt_len + 4, &empty[0], 0, &u)
		for i in 0 .. digest_bytes {
			unsafe { t[i] = u[i] }
		}
		for round := u64(1); round < iterations; round++ {
			hmac_two(password, password_len, &u[0], digest_bytes, &empty[0], 0, &u)
			for i in 0 .. digest_bytes {
				unsafe { t[i] ^= u[i] }
			}
		}
		at := (block - 1) * digest_bytes
		count := if output_len - at < digest_bytes { output_len - at } else { digest_bytes }
		for i in u64(0) .. count {
			unsafe { output[at + i] = t[i] }
		}
	}
	return true
}

// Constant-time comparison of two 32-byte tags.
pub fn equal(left &u8, right &u8) bool {
	mut difference := u8(0)
	for i in 0 .. digest_bytes {
		difference |= unsafe { left[i] ^ right[i] }
	}
	return difference == 0
}
