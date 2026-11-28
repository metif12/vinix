// SPDX-License-Identifier: GPL-2.0-or-later
//
// Host tests of the kernel KDF against published vectors:
// RFC 4231 (HMAC-SHA256) and the standard PBKDF2-HMAC-SHA256 vectors.
module kdf

const digits = '0123456789abcdef'

fn nibble(c u8) u8 {
	if c >= 48 && c <= 57 {
		return c - 48
	}
	return c - 87
}

fn unhex(text string) []u8 {
	mut out := []u8{len: text.len / 2}
	for i in 0 .. out.len {
		out[i] = (nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1])
	}
	return out
}

fn as_hex(bytes []u8) string {
	mut out := ''
	for byte in bytes {
		out += digits[byte >> 4].ascii_str()
		out += digits[byte & 15].ascii_str()
	}
	return out
}

fn test_hmac_sha256_rfc4231_case_1() {
	key := [20]u8{init: 0x0b}
	data := 'Hi There'.bytes()
	mut got := [32]u8{}
	authenticate(&key[0], u64(key.len), data.data, u64(data.len), &got)
	assert as_hex(got[0..]) == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
}

fn test_pbkdf2_one_round() {
	password := 'password'.bytes()
	salt := 'salt'.bytes()
	mut output := [32]u8{}
	mut workspace := [64]u8{}
	assert derive(password.data, u64(password.len), salt.data, u64(salt.len), 1,
		&output[0], u64(output.len), &workspace[0], u64(workspace.len))
	assert as_hex(output[0..]) == '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
}

fn test_pbkdf2_two_rounds() {
	password := 'password'.bytes()
	salt := 'salt'.bytes()
	mut output := [32]u8{}
	mut workspace := [64]u8{}
	assert derive(password.data, u64(password.len), salt.data, u64(salt.len), 2,
		&output[0], u64(output.len), &workspace[0], u64(workspace.len))
	assert as_hex(output[0..]) == 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
}

fn test_pbkdf2_many_rounds() {
	password := 'password'.bytes()
	salt := 'salt'.bytes()
	mut output := [32]u8{}
	mut workspace := [64]u8{}
	assert derive(password.data, u64(password.len), salt.data, u64(salt.len), 4096,
		&output[0], u64(output.len), &workspace[0], u64(workspace.len))
	assert as_hex(output[0..]) == 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
}

fn test_pbkdf2_multiple_blocks_and_short_output() {
	password := 'password'.bytes()
	salt := 'salt'.bytes()
	mut output := [40]u8{}
	mut workspace := [64]u8{}
	assert derive(password.data, u64(password.len), salt.data, u64(salt.len), 1,
		&output[0], u64(output.len), &workspace[0], u64(workspace.len))
	assert as_hex(output[0..32]) == '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
	// The second block was checked against OpenSSL for the same inputs and
	// dkLen 40.
	assert as_hex(output[32..40]) == '4dbf3a2f3dad3377'
}

fn test_bad_arguments_are_refused() {
	password := 'password'.bytes()
	salt := 'salt'.bytes()
	mut output := [32]u8{}
	mut workspace := [64]u8{}
	assert !derive(password.data, u64(password.len), salt.data, u64(salt.len), 0,
		&output[0], u64(output.len), &workspace[0], u64(workspace.len))
	assert !derive(password.data, u64(password.len), salt.data, u64(salt.len), 1,
		&output[0], u64(output.len), &workspace[0], u64(salt.len) + 3)
}

fn test_tag_comparison_is_exact() {
	a := unhex('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
	mut b := a.clone()
	assert equal(unsafe { &a[0] }, unsafe { &b[0] })
	b[31] ^= 1
	assert !equal(unsafe { &a[0] }, unsafe { &b[0] })
}
