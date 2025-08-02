package opaque

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func abhor(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
}

func TestOPRF(t *testing.T) {
	var xx = hex.EncodeToString

	expectedBlind, err := hex.DecodeString("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364")
	abhor(t, err)
	sk, err := hex.DecodeString("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf")
	abhor(t, err)

	randomScalarForTesting = expectedBlind
	msg := []byte{0}
	blind, belem, err := BlindP256(msg)
	abhor(t, err)
	if !bytes.Equal(blind, expectedBlind) {
		t.Fatalf("Blind: blind = %x, expected %x", blind, expectedBlind)
	}
	wantbelem := "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d"
	if xx(belem) != wantbelem {
		t.Fatalf("Blind: blinded element = %x, expected %v", belem, wantbelem)
	}

	velem, err := BlindEvaluateP256(sk, belem)
	abhor(t, err)
	wantvelem := "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832"
	if xx(velem) != wantvelem {
		t.Fatalf("BlindEvaluate: evaluated element = %x, expected %v", velem, wantvelem)
	}

	output, err := BlindFinalizeP256(msg, blind, velem)
	abhor(t, err)
	wantoutput := "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd"
	if xx(output) != wantoutput {
		t.Fatalf("BlindFinalize: output = %x, expected %v", output, wantoutput)
	}

}
