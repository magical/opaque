package opaque

import (
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestExpandMessageXmd(t *testing.T) {
	// https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmdsha-256
	msg := []byte("abc")
	DST := "QUUX-V01-CS02-with-expander-SHA256-128"
	expected := "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
	out := expand_message_xmd(msg, DST, 0x20)
	checkBytes(t, "out", out, expected)

	expected = "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2" +
		"fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b" +
		"664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221" +
		"b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425" +
		"cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"

	out = expand_message_xmd(msg, DST, 0x80)
	checkBytes(t, "out", out, expected)
}

func TestHashToFieldP256(t *testing.T) {
	// https://www.rfc-editor.org/rfc/rfc9380.html#name-p256_xmdsha-256_sswu_nu_
	msg := []byte("abc")
	DST := "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_"
	out := hashToFieldP256(msg, DST)
	checkBytes(t, "out", out, "c7f96eadac763e176629b09ed0c11992225b3a5ae99479760601cbd69c221e58")
}

func TestOpaque(t *testing.T) {
	password := []byte("CorrectHorseBatteryStaple")

	blind, err := hex.DecodeString("c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1")
	abhor(t, err)
	fixedScalarForTesting = blind
	defer func() { fixedScalarForTesting = nil }()

	clientNonce, err := hex.DecodeString("ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1")
	abhor(t, err)
	fixedNonceForTesting = clientNonce
	defer func() { fixedNonceForTesting = nil }()

	clientSeed, err := hex.DecodeString("633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc")
	abhor(t, err)
	fixedSeedForTesting = clientSeed
	defer func() { fixedSeedForTesting = nil }()

	var c ClientState
	ke1, err := c.GenerateKE1(password)
	abhor(t, err)
	fmt.Printf("% x\n", c.blind)
	fmt.Printf("% x\n", c.clientPrivKeyshare)
	fmt.Printf("% x\n", ke1.credentialRequest.blindedMessage)
	fmt.Printf("% x\n", ke1.authRequest.clientNonce)
	fmt.Printf("% x\n", ke1.authRequest.clientPubKeyshare)
	ok := checkBytes(t, "client priv keyshare", c.clientPrivKeyshare,
		"2d3f3aafdcb640eec91754b63837163ef88b0cf42119e2bf5a8922a2ff72c818")
	ok2 := checkBytes(t, "pub keyshare", ke1.authRequest.clientPubKeyshare,
		"022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6")
	if !ok || !ok2 {
		return
	}

	applicationContext = []byte("OPAQUE-POC")

	serverID := []byte(nil)
	clientID := []byte(nil)
	serverPrivKey, err := hex.DecodeString("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5")
	abhor(t, err)
	serverPubKey, err := hex.DecodeString("035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874")
	abhor(t, err)
	clientPubKey, err := hex.DecodeString("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214")
	abhor(t, err)
	envelope, err := hex.DecodeString("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8")
	abhor(t, err)
	randomizedPassword, err := hex.DecodeString("06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0")
	abhor(t, err)
	r := hkdf.Expand(NewHash, randomizedPassword, []byte("MaskingKey"))
	maskingKey := make([]byte, Nh)
	_, err = io.ReadFull(r, maskingKey)
	abhor(t, err)
	fmt.Printf("masking key = %x\n", maskingKey)
	clientRegRecord := &ClientRegRecord{
		pubKey:     clientPubKey,
		maskingKey: maskingKey,
		envelope:   envelope,
	}
	credID := []byte("1234")
	oprfSeed, err := hex.DecodeString("62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2")
	abhor(t, err)
	serverSeed, err := hex.DecodeString("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f")
	abhor(t, err)
	serverNonce, err := hex.DecodeString("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1")
	abhor(t, err)
	maskingNonce, err := hex.DecodeString("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d")
	abhor(t, err)

	// server pub keyshare: 03c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b
	// client pub keyshare: 022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6

	fixedSeedForTesting = serverSeed
	fixedNonceForTesting = serverNonce
	fixedNonceForTesting2 = maskingNonce
	defer func() { fixedNonceForTesting2 = nil }()

	var s ServerState
	ke2, err := s.GenerateKE2(serverID, serverPrivKey, serverPubKey, clientRegRecord, credID, oprfSeed, ke1, clientID)
	abhor(t, err)
	fmt.Println("KE2")
	fmt.Printf("% x\n", ke2.credentialResponse.evaluatedMessage) // ok
	fmt.Printf("% x\n", ke2.credentialResponse.maskingNonce)     // ok
	fmt.Printf("|% x|\n", ke2.credentialResponse.maskedResponse)
	// pubkey ok
	// envelope ok
	fmt.Printf("% x\n", ke2.authResponse.serverNonce)       // ok
	fmt.Printf("% x\n", ke2.authResponse.serverPubKeyshare) // ok
	fmt.Printf("% x\n", ke2.authResponse.serverMAC)
	t.Error(".")
}

func checkBytes(t *testing.T, name string, actual []byte, expected string) bool {
	t.Helper()
	if fmt.Sprintf("%x", actual) != expected {
		t.Errorf("%s: got %x want %v", name, actual, expected)
		return false
	}
	return true
}
