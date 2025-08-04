package opaque

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"filippo.io/nistec"
)

const oprfContextString = "OPRFV1-\x00-"
const oprfSuite = "P256-SHA256"

// TODO: Applications MUST check that input Element values received over the wire are not the group identity element. This check is handled after deserializing Element values; see Section 4 for more information and requirements on input validation for each ciphersuite.

var fixedScalarForTesting []byte

func randomScalar() []byte {
	if fixedScalarForTesting != nil {
		return bytes.Clone(fixedScalarForTesting)
	}
	//  4.7.2. Random Number Generation Using Extra Random Bits
	// Generate a random byte array with L = ceil(((3 * ceil(log2(G.Order()))) / 2) / 8) bytes, and interpret it as an integer; reduce the integer modulo G.Order(), and return the result. See [RFC9380], Section 5 for the underlying derivation of L.
	const L = (256 + 128) / 8
	var buf = make([]byte, L)
	if _, err := rand.Read(buf); err != nil {
		panic("entropy failure")
	}
	e := new(big.Int).SetBytes(buf) // big endian
	// TODO: constant time?
	e.Mod(e, p256Order())
	scalar := e.Bytes()
	// left pad with zeros, if necessary
	if len(scalar) < Nok {
		padded := make([]byte, Nok)
		copy(padded[Nok-len(scalar):Nok], scalar[:])
		return padded
	}
	return scalar
}

var p256Order = sync.OnceValue(func() *big.Int {
	n, ok := new(big.Int).SetString("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 0)
	if !ok {
		panic("failed to init p256Order")
	}
	return n
})

func BlindP256(input []byte) (blind, blindedElement []byte, err error) {
	point := HashToGroupP256(input)
	if isIdentity(point) {
		// The identity point is not allowed, per the spec
		return nil, nil, InvalidInputError
	}
	blind = randomScalar()
	blindedPoint, err := point.ScalarMult(point, blind)
	if err != nil {
		// this should only happen if blind is not the correct length (32 bytes)
		// which should be impossible
		panic("internal error:" + err.Error())
	}
	blindedElement = blindedPoint.BytesCompressed()
	return blind, blindedElement, nil
}
func isIdentity(p *nistec.P256Point) bool {
	return false //TODO
}

func BlindEvaluateP256(skS, blindedElement []byte) ([]byte, error) {
	blindedPoint, err := nistec.NewP256Point().SetBytes(blindedElement)
	if err != nil {
		return nil, err
	}
	evaluatedPoint, err := blindedPoint.ScalarMult(blindedPoint, skS)
	if err != nil {
		// skS is the wrong size
		return nil, fmt.Errorf("bad skS: %w", err)
	}
	evaluatedElement := evaluatedPoint.BytesCompressed()
	return evaluatedElement, nil
}

func BlindFinalizeP256(input, blind, evaluatedElement []byte) ([]byte, error) {
	if len(input) > 0xffff {
		return nil, errors.New("input too large")
	}
	evaluatedPoint, err := nistec.NewP256Point().SetBytes(evaluatedElement)
	if err != nil {
		return nil, err
	}
	inverseBlind, err := nistec.P256OrdInverse(blind)
	if err != nil {
		return nil, err
	}
	evaluatedPoint.ScalarMult(evaluatedPoint, inverseBlind)
	unblindedElement := evaluatedPoint.BytesCompressed()
	h := NewHash()
	h.Write([]byte{byte(len(input) >> 8), byte(len(input))})
	h.Write(input)
	h.Write([]byte{byte(len(unblindedElement) >> 8), byte(len(unblindedElement))})
	h.Write(unblindedElement)
	h.Write([]byte("Finalize"))
	return h.Sum(nil), nil
}

var InvalidInputError = errors.New("invalid input")

func HashToGroupP256(msg []byte) *nistec.P256Point {
	// Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO_ [RFC9380] and DST = "HashToGroup-" || contextString

	// Steps:
	// 1. u = hash_to_field(msg, 2)
	// 2. Q0 = map_to_curve(u[0])
	// 3. Q1 = map_to_curve(u[1])
	// 4. R = Q0 + Q1              # Point addition
	// 5. P = clear_cofactor(R)
	// 6. return P

	const L = (256 + 128) / 8
	const dst = "HashToGroup-" + oprfContextString + oprfSuite
	expandedBytes := expand_message_xmd(msg, dst, L+L)
	p, err := nistec.HashToCurve(expandedBytes)
	if err != nil {
		panic(err)
	}
	return p
}

type oprfFuncs struct {
	blind    func(input []byte) (blind, blindedElement []byte, _ error)
	finalize func(input, blind, evaluated []byte) ([]byte, error)
	evaluate func(sk, blindedElement []byte) (evaluatedElement []byte, err error)
}

var oprfP256 = &oprfFuncs{
	blind:    BlindP256,
	finalize: BlindFinalizeP256,
	evaluate: BlindEvaluateP256,
}

func (v *oprfFuncs) Blind(input []byte) (blind, blindedElement []byte, _ error) {
	return v.blind(input)
}
func (v *oprfFuncs) Finalize(input, blind, evaluated []byte) ([]byte, error) {
	return v.finalize(input, blind, evaluated)
}
func (v *oprfFuncs) BlindEvaluate(sk, blindedElement []byte) (evaluatedElement []byte, err error) {
	return v.evaluate(sk, blindedElement)
}
