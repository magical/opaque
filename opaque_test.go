package opaque

import "testing"
import "fmt"

func TestExpandMessageXmd(t *testing.T) {
	// https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmdsha-256
	msg := []byte("abc")
	DST := "QUUX-V01-CS02-with-expander-SHA256-128"
	expected := "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
	out := expand_message_xmd(msg, DST, 0x20)
	actual := fmt.Sprintf("%x", out)
	if expected != actual {
		t.Errorf("want %q got %q", expected, actual)
	}

	expected = "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2" +
		"fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b" +
		"664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221" +
		"b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425" +
		"cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"

	out = expand_message_xmd(msg, DST, 0x80)
	actual = fmt.Sprintf("%x", out)
	if expected != actual {
		t.Errorf("want %q got %q", expected, actual)
	}
}

func TestHashToFieldP256(t *testing.T) {
	// https://www.rfc-editor.org/rfc/rfc9380.html#name-p256_xmdsha-256_sswu_nu_
	msg := []byte("abc")
	DST := "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_"
	expected := "c7f96eadac763e176629b09ed0c11992225b3a5ae99479760601cbd69c221e58"
	out := hashToFieldP256(msg, DST)
	actual := fmt.Sprintf("%x", out)
	if expected != actual {
		t.Errorf("want %q got %q", expected, actual)
	}
}
