package opaque

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
	"strings"
	"sync"

	"filippo.io/nistec"
	"golang.org/x/crypto/hkdf"
)

// https://eprint.iacr.org/2018/163.pdf
// OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks
// Stanislaw Jarecki, Hugo Krawczyk, and Jiayu Xu
// §6

// security parameter tau = 128?
// Group G of prime order q, |q| = 2tau
// hash function H with ranges 2^2tau
// hash function H' with range G
// pseudorandom funciton f with range 2^2tau
// AEAD AuthEnc, AuthDec
//

// https://datatracker.ietf.org/doc/rfc9807/
// The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol
// H. Krawczyk, K. Lewi, C. A. Wood

// profile: P256-SHA256, HKDF-SHA-256, HMAC-SHA-256, SHA-256, scrypt(S = zeroes(16), N = 32768, r = 8, p = 1, dkLen = 32), P-256

func Stretch(b []byte) ([]byte, error) {
	// TODO: scrypt
	// TODO: should take a context.Context, for cancellation
	return b, nil
}

var NewHash = sha256.New

var applicationContext []byte

type BlindSigner interface {
	Blind(input []byte) (blind, blindedElement []byte, _ error)
	Finalize(input, blind, evaluated []byte) ([]byte, error)
}

type BlindEvaluator interface {
	// can return a deserialization error
	BlindEvaluate(sk, blindedElement []byte) (evaluatedElement []byte, err error)
}

// Deterministically derived a key pair from a 32-byte seed
// and an (optional) info string.
func DeriveKeyPair(seed [32]byte, info string) (sk, pk []byte, err error) {
	return deriveKeyPair(seed, info)
}

func hkdfExpand(h func() hash.Hash, secret []byte, info string, size int) []byte {
	out := make([]byte, size)
	r := hkdf.Expand(h, secret, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf failure") // shouldn't happen
	}
	return out
}

const Noe = 33 //size of serialized element
const Nok = 32 //size of OPRF private key

type ClientState struct {
	// oprf state
	password []byte
	blind    []byte
	// AKE state
	clientPrivKeyshare []byte
	ke1                KE1
}

type KE1 struct {
	credentialRequest *CredentialRequest
	authRequest       AuthRequest
}
type KE2 struct {
	credentialResponse *CredentialResponse
	authResponse       AuthResponse
}
type KE3 struct{ clientMAC []byte }

func (c *ClientState) GenerateKE1(password []byte) (KE1, error) {
	request, blind := CreateCredentialRequest(password)
	c.password = password
	c.blind = blind
	ke1, err := c.AuthClientStart(request)
	if err != nil {
		return KE1{}, err
	}
	return ke1, nil
}

type ServerState struct {
	expectedClientMAC []byte
	sessionKey        []byte
}

type ClientRegRecord struct {
	pubKey, maskingKey, envelope []byte
}

func (s *ServerState) GenerateKE2(serverID, privKey, pubKey []byte, clientRegRecord *ClientRegRecord, credID, oprfSeed []byte, ke1 KE1, clientID []byte) (KE2, error) {
	response, err := CreateCredentialResponse(ke1.credentialRequest, pubKey, clientRegRecord, credID, oprfSeed)
	if err != nil {
		return KE2{}, err
	}
	credentials := CreateCleartextCredentials(pubKey, clientRegRecord.pubKey, serverID, clientID)
	authResponse, err := s.AuthServerRespond(credentials, privKey, clientRegRecord.pubKey, ke1, response)
	if err != nil {
		return KE2{}, err
	}

	ke2 := KE2{response, *authResponse}
	return ke2, nil
}

var ClientAuthenticationError = errors.New("client authentication error")

func (c *ClientState) GenerateKE3(clientID, serverID []byte, ke2 KE2) (ke3 KE3, sessionKey, exportKey []byte, err error) {
	privKey, credentials, exportKey, err := RecoverCredentials(c.password, c.blind, ke2.credentialResponse, serverID, clientID)
	if err != nil {
		return KE3{}, nil, nil, err
	}
	ke3, sessionKey, err = c.AuthClientFinalize(credentials, privKey, ke2)
	if err != nil {
		return KE3{}, nil, nil, err
	}
	return ke3, sessionKey, exportKey, nil
}

func (s *ServerState) Finish(ke3 KE3) (sessionKey []byte, err error) {
	if !hmac.Equal(ke3.clientMAC, s.expectedClientMAC) {
		return nil, ClientAuthenticationError
	}
	return s.sessionKey, nil
}

type CredentialRequest struct{ blindedMessage []byte }
type CredentialResponse struct{ evaluatedMessage, maskingNonce, maskedResponse []byte }
type CleartextCredentials struct{ serverPubKey, serverID, clientID []byte }

func SerializeElement(x []byte) []byte            { return x }
func DeserializeElement(x []byte) ([]byte, error) { return x, nil }

func CreateCredentialRequest(password []byte) (*CredentialRequest, []byte) {
	var oprf BlindSigner = oprfP256
	blind, blindElement, err := oprf.Blind(password)
	if err != nil {
		panic(err) // TODO
	}
	blindMessage := SerializeElement(blindElement)
	return &CredentialRequest{blindMessage}, blind
}

var fixedNonceForTesting []byte
var fixedNonceForTesting2 []byte

func newRandomNonce() []byte {
	if fixedNonceForTesting != nil {
		return bytes.Clone(fixedNonceForTesting)
	}
	b := make([]byte, Nn)
	rand.Read(b)
	return b
}
func newRandomNonce2() []byte {
	if fixedNonceForTesting2 != nil {
		return bytes.Clone(fixedNonceForTesting2)
	}
	return newRandomNonce()
}

var fixedSeedForTesting []byte

func newRandomSeed() [Nseed]byte {
	var b [Nseed]byte
	rand.Read(b[:])
	if fixedSeedForTesting != nil {
		copy(b[:], fixedSeedForTesting)
	}
	return b
}

func CreateCredentialResponse(request *CredentialRequest, pubKey []byte, clientRegRecord *ClientRegRecord, credID, oprfSeed []byte) (*CredentialResponse, error) {
	var seed = (*[Nok]byte)(hkdfExpand(NewHash, oprfSeed, concats(credID, "OprfKey"), Nok))

	oprfKey, _, err := DeriveKeyPair(*seed, "OPAQUE-DeriveKeyPair")
	if err != nil {
		return nil, err
	}
	blindedElement, err := DeserializeElement(request.blindedMessage)
	if err != nil {
		return nil, err
	}
	var oprf BlindEvaluator = oprfP256
	evaluatedElement, err := oprf.BlindEvaluate(oprfKey, blindedElement)
	if err != nil {
		return nil, err
	}
	evaluatedMessage := SerializeElement(evaluatedElement)

	maskingNonce := newRandomNonce2()

	var xorpad = hkdfExpand(NewHash, clientRegRecord.maskingKey, concats(maskingNonce, "CredentialResponsePad"), Npk+Nn+Nm)
	var maskedResponse []byte
	maskedResponse = append(maskedResponse, pubKey...) // server public key
	maskedResponse = append(maskedResponse, clientRegRecord.envelope...)
	subtle.XORBytes(maskedResponse, maskedResponse, xorpad)

	return &CredentialResponse{
		evaluatedMessage, maskingNonce, maskedResponse,
	}, nil
}

const (
	Npk = 33
	Nn  = Nseed
	Nm  = sha256.Size
)

func RecoverCredentials(password []byte, blind []byte, response *CredentialResponse, serverID, clientID []byte) (privKey []byte, credentials *CleartextCredentials, exportKey []byte, err error) {
	var oprf BlindSigner = oprfP256
	oprfOutput, err := oprf.Finalize(password, blind, response.evaluatedMessage)
	if err != nil {
		return nil, nil, nil, err
	}
	stretchedOutput, err := Stretch(oprfOutput)
	if err != nil {
		return nil, nil, nil, err
	}
	kdfInfo := append(oprfOutput, stretchedOutput...)
	randomizedPassword := hkdf.Extract(NewHash, kdfInfo, nil)
	maskingKey := hkdfExpand(NewHash, randomizedPassword, "MaskingKey", Nh)
	xorpad := hkdfExpand(NewHash, maskingKey, concats(response.maskingNonce, "CredentialResponsePad"), Npk+Nn+Nm)
	var unmaskedResponse = make([]byte, len(response.maskedResponse))
	subtle.XORBytes(unmaskedResponse, response.maskedResponse, xorpad)

	pubKey := unmaskedResponse[:Npk:Npk]
	envelope := unmaskedResponse[Npk:]

	clientKey, credentials, exportKey, err := Recover(randomizedPassword, pubKey, envelope, serverID, clientID)
	if err != nil {
		return nil, nil, nil, err
	}
	return clientKey, credentials, exportKey, nil
}

func concats(a []byte, b string) string {
	var out []byte
	out = append(out, a...)
	out = append(out, b...)
	return string(out)
}

var EnvelopeRecoveryError = errors.New("opaque: failed to recover envelope")

const Nh = sha256.Size
const Nseed = 32

var ignoreAuthErrorsForTesting = false

func Recover(randomizedPassword, pubKey, envelope, serverID, clientID []byte) (privKey []byte, credentials *CleartextCredentials, exportKey []byte, err error) {
	envelopeNonce := envelope[0:Nn]
	envelopeAuthTag := envelope[Nn : Nn+Nm]

	authKey := hkdfExpand(NewHash, randomizedPassword, concats(envelopeNonce, "AuthKey"), Nh)
	exportKey = hkdfExpand(NewHash, randomizedPassword, concats(envelopeNonce, "ExportKey"), Nh)
	seed := (*[Nseed]byte)(hkdfExpand(NewHash, randomizedPassword, concats(envelopeNonce, "PrivateKey"), Nseed))

	//clientPrivKey, clientPubKey := DeriveDiffieHellmanKeyPair(seed)
	clientPrivKey, clientPubKey, err := DeriveKeyPair(*seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return nil, nil, nil, err
	}
	credentials = CreateCleartextCredentials(pubKey, clientPubKey, serverID, clientID)
	sidlen := len(credentials.serverID)
	cidlen := len(credentials.clientID)
	hm := hmac.New(NewHash, authKey)
	hm.Write(envelopeNonce)
	hm.Write(credentials.serverPubKey)
	hm.Write([]byte{byte(sidlen >> 8), byte(sidlen)})
	hm.Write(credentials.serverID)
	hm.Write([]byte{byte(cidlen >> 8), byte(cidlen)})
	hm.Write(credentials.clientID)
	tag := hm.Sum(nil)
	if !hmac.Equal(envelopeAuthTag, tag) && !ignoreAuthErrorsForTesting {
		secureClear(clientPrivKey)
		secureClear(clientPubKey)
		secureClear(seed[:])
		secureClear(exportKey)
		secureClear(authKey)
		return nil, nil, nil, EnvelopeRecoveryError
	}
	return clientPrivKey, credentials, exportKey, nil
}

func CreateCleartextCredentials(serverPubKey, clientPubKey, serverID, clientID []byte) *CleartextCredentials {
	if len(serverID) == 0 {
		serverID = serverPubKey
	}
	if len(clientID) == 0 {
		clientID = clientPubKey
	}
	return &CleartextCredentials{
		serverPubKey,
		serverID,
		clientID,
	}
}

///

type AuthRequest struct{ clientNonce, clientPubKeyshare []byte }
type AuthResponse struct{ serverNonce, serverPubKeyshare, serverMAC []byte }

func (c *ClientState) AuthClientStart(request *CredentialRequest) (KE1, error) {
	nonce := newRandomNonce()
	seed := newRandomSeed()
	// DeriveDiffieHellmanKeyPair
	clientPrivKeyshare, clientPubKeyshare, err := DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return KE1{}, err
	}
	c.clientPrivKeyshare = clientPrivKeyshare
	c.ke1 = KE1{request, AuthRequest{nonce, clientPubKeyshare}}
	return c.ke1, nil
}

func (s *ServerState) AuthServerRespond(creds *CleartextCredentials, privKey []byte, clientPubKey []byte, ke1 KE1, credResponse *CredentialResponse) (*AuthResponse, error) {
	//fmt.Printf("creds: %#v\n", creds)
	//fmt.Printf("privkey: %x\n", privKey)
	//fmt.Printf("clientPubKey: %x\n", clientPubKey)
	//fmt.Printf("ke1: %#v\n", &ke1)
	//fmt.Printf("credResponse: %#v\n", credResponse)
	serverNonce := newRandomNonce()
	seed := newRandomSeed()
	// DeriveDiffieHellmanKeyPair
	serverPrivKeyshare, serverPubKeyshare, err := DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return nil, err
	}
	//fmt.Printf("server priv keyshare: %x\n", serverPrivKeyshare)
	//fmt.Printf("server pub keyshare:  %x\n", serverPubKeyshare)
	ke2 := KE2{credResponse, AuthResponse{serverNonce, serverPubKeyshare, nil}}
	ph := hashPreamble(creds.clientID, ke1, creds.serverID, ke2)
	preambleHash := ph.Sum(nil)

	dh1 := DiffieHellman(serverPrivKeyshare, ke1.authRequest.clientPubKeyshare)
	dh2 := DiffieHellman(privKey, ke1.authRequest.clientPubKeyshare)
	dh3 := DiffieHellman(serverPrivKeyshare, clientPubKey)
	var ikm []byte
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	km2, km3, sessionKey := DeriveKeys(ikm, preambleHash)
	//fmt.Printf("km2 %x\n", km2)
	//fmt.Printf("km3 %x\n", km3)
	hm := hmac.New(NewHash, km2)
	hm.Write(preambleHash)
	serverMAC := hm.Sum(nil)
	ph.Write(serverMAC)
	hm = hmac.New(NewHash, km3)
	hm.Write(ph.Sum(nil))
	s.expectedClientMAC = hm.Sum(nil)
	s.sessionKey = sessionKey
	return &AuthResponse{serverNonce, serverPubKeyshare, serverMAC}, nil
}

var ServerAuthenticationError = errors.New("opaque: server authentication error")

func (c *ClientState) AuthClientFinalize(creds *CleartextCredentials, privKey []byte, ke2 KE2) (_ KE3, sessionKey []byte, err error) {
	dh1 := DiffieHellman(c.clientPrivKeyshare, ke2.authResponse.serverPubKeyshare)
	dh2 := DiffieHellman(c.clientPrivKeyshare, creds.serverPubKey)
	dh3 := DiffieHellman(privKey, ke2.authResponse.serverPubKeyshare)
	var ikm []byte
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	ph := hashPreamble(creds.clientID, c.ke1, creds.serverID, ke2)
	preambleHash := ph.Sum(nil)
	km2, km3, sessionKey := DeriveKeys(ikm, preambleHash)
	hm := hmac.New(NewHash, km2)
	hm.Write(preambleHash)
	expectedTag := hm.Sum(nil)
	if !hmac.Equal(expectedTag, ke2.authResponse.serverMAC) && !ignoreAuthErrorsForTesting {
		return KE3{}, nil, ServerAuthenticationError
	}
	// MAC(Hash(preamble || serverTag))
	hm = hmac.New(NewHash, km3)
	ph.Write(expectedTag)
	hm.Write(ph.Sum(nil))
	clientMAC := hm.Sum(nil)
	return KE3{clientMAC}, sessionKey, nil
}

func hashPreamble(clientID []byte, ke1 KE1, serverID []byte, ke2 KE2) hash.Hash {
	//dumpPreamble(clientID, ke1, serverID, ke2)
	h := NewHash()
	h.Write([]byte("OPAQUEv1-"))
	h.Write([]byte{byte(len(applicationContext) >> 8), byte(len(applicationContext))})
	h.Write(applicationContext)
	h.Write([]byte{byte(len(clientID) >> 8), byte(len(clientID))})
	h.Write(clientID)
	h.Write(ke1.credentialRequest.blindedMessage)
	h.Write(ke1.authRequest.clientNonce)
	h.Write(ke1.authRequest.clientPubKeyshare)
	h.Write([]byte{byte(len(serverID) >> 8), byte(len(serverID))})
	h.Write(serverID)
	h.Write(ke2.credentialResponse.evaluatedMessage)
	h.Write(ke2.credentialResponse.maskingNonce)
	h.Write(ke2.credentialResponse.maskedResponse)
	h.Write(ke2.authResponse.serverNonce)
	h.Write(ke2.authResponse.serverPubKeyshare)
	return h
}

/*
func dumpPreamble(clientID []byte, ke1 KE1, serverID []byte, ke2 KE2) {
	w := func(b []byte) {
		if printable(b) {
			fmt.Printf("preamble | %q = % [1]x\n", b)
		} else {
			fmt.Printf("preamble | % x\n", b)
		}
	}
	w([]byte("OPAQUEv1-"))
	w([]byte{byte(len(applicationContext) >> 8), byte(len(applicationContext))})
	w(applicationContext)
	w([]byte{byte(len(clientID) >> 8), byte(len(clientID))})
	w(clientID)
	w(ke1.credentialRequest.blindedMessage)
	w(ke1.authRequest.clientNonce)
	w(ke1.authRequest.clientPubKeyshare)
	w([]byte{byte(len(serverID) >> 8), byte(len(serverID))})
	w(serverID)
	w(ke2.credentialResponse.evaluatedMessage)
	w(ke2.credentialResponse.maskingNonce)
	w(ke2.credentialResponse.maskedResponse)
	w(ke2.authResponse.serverNonce)
	w(ke2.authResponse.serverPubKeyshare)
}
*/

func printable(b []byte) bool {
	for _, c := range b {
		if !(0x20 <= c && c <= 0x7E) {
			return false
		}
	}
	return true
}

func DiffieHellman(privKey, pubKey []byte) []byte {
	//fmt.Printf("Diffie hellman:\npriv %x\npub  %x\n", privKey, pubKey)
	p := nistec.NewP256Point()
	if _, err := p.SetBytes(pubKey); err != nil {
		panic(err)
	}
	if _, err := p.ScalarMult(p, privKey); err != nil {
		panic(err)
	}
	//fmt.Printf("out  %x\n", p.BytesCompressed())
	return p.BytesCompressed()
}

func DeriveKeys(ikm, preambleHash []byte) (km2, km3, sessionKey []byte) {
	prk := hkdf.Extract(NewHash, ikm, nil)
	handshakeSecret := DeriveSecret(prk, "HandshakeSecret", preambleHash)
	sessionKey = DeriveSecret(prk, "SessionKey", preambleHash)
	//fmt.Printf("preamble hash: %x\n", preambleHash)
	//fmt.Printf("handshake secret: %x\n", handshakeSecret)
	//fmt.Printf("session key: %x\n", sessionKey)
	km2 = DeriveSecret(handshakeSecret, "ServerMAC", nil)
	km3 = DeriveSecret(handshakeSecret, "ClientMAC", nil)
	return km2, km3, sessionKey
}

const Nx = sha256.Size

func DeriveSecret(baseSecret []byte, label string, transcriptHash []byte) []byte {
	// TODO: check label and transcriptHash length
	var info strings.Builder
	info.Write([]byte{byte(Nx >> 8), byte(Nx)})
	info.Write([]byte{byte(len("OPAQUE-") + len(label))})
	info.WriteString("OPAQUE-")
	info.WriteString(label)
	info.Write([]byte{byte(len(transcriptHash))})
	info.Write(transcriptHash)
	return hkdfExpand(NewHash, baseSecret, info.String(), Nx)
}

// Deterministic key generation from RFC9497
//
// OPRF(P-256, SHA-256)
// https://www.rfc-editor.org/rfc/rfc9497.html#name-oprfp-256-sha-256
//

var DeriveKeyPairError = errors.New("failed to derive key pair")

//const contextString = "OPRFV1-\x00-OPAQUE-POC"

func deriveKeyPair(seed [32]byte, info string) (sk, pk []byte, err error) {
	l := len(info)
	if l > 65535 {
		panic("info too long")
	}
	var deriveInput []byte
	deriveInput = append(deriveInput, seed[:]...)
	deriveInput = append(deriveInput, byte(l>>8), byte(l))
	deriveInput = append(deriveInput, info...)
	deriveInput = append(deriveInput, 0) // counter
	for counter := 0; counter < 256; counter++ {
		deriveInput[len(deriveInput)-1] = uint8(counter)
		// RFC9497
		// Section 4.3:
		//  Use hash_to_field from [RFC9380] using L = 48,
		//  expand_message_xmd with SHA-256, DST = "HashToScalar-" ||
		//  contextString, and a prime modulus equal to Group.Order().
		// Section 3.2.1:
		//  DST="DeriveKeyPair" || contextString
		sk := hashToScalarP256(deriveInput, "DeriveKeyPairOPRFV1-\x00-P256-SHA256")
		// note: can't fail
		if sk != nil {
			pk := nistec.NewP256Point()
			if _, err := pk.ScalarBaseMult(sk); err == nil {
				return sk, SerializeElement(pk.BytesCompressed()), nil
			}
		}
	}
	return nil, nil, DeriveKeyPairError
}

func hashToScalarP256(msg []byte, DST string) []byte {
	const L = 48 // (256 + 128) / 8
	uniform_bytes := expand_message_xmd(msg, DST, L)
	e := new(big.Int).SetBytes(uniform_bytes) // big endian
	// reduce scalar tv modulo the order of P-256
	// TODO: constant time?
	e.Mod(e, p256Order())
	return e.Bytes()
}

// https://www.rfc-editor.org/rfc/rfc9380.html#name-suites-for-nist-p-256
func hashToFieldP256(msg []byte, DST string) []byte {
	const L = 48 // (256 + 128) / 8
	uniform_bytes := expand_message_xmd(msg, DST, L)
	e := new(big.Int).SetBytes(uniform_bytes) // big endian
	// reduce scalar tv modulo the order of the P-256's prime field
	// TODO: constant time?
	e.Mod(e, p256Prime())
	return e.Bytes()
}

var p256Prime = sync.OnceValue(func() *big.Int {
	// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
	z := big.NewInt(-1)
	one := big.NewInt(1)
	z = z.Add(z, new(big.Int).Lsh(one, 96))
	z = z.Add(z, new(big.Int).Lsh(one, 192))
	z = z.Sub(z, new(big.Int).Lsh(one, 224))
	z = z.Add(z, new(big.Int).Lsh(one, 256))
	return z
})

func expand_message_xmd(msg []byte, DST string, len_in_bytes int) []byte {
	var dstBytesWithLength = make([]byte, 0, len(DST)+1)
	dstBytesWithLength = append(dstBytesWithLength, DST...)
	dstBytesWithLength = append(dstBytesWithLength, uint8(len(DST)))

	var counter = make([]byte, 1)
	h := NewHash()
	h.Write(make([]byte, h.BlockSize()))
	h.Write(msg)
	h.Write([]byte{byte(len_in_bytes >> 8), byte(len_in_bytes)})
	counter[0] = 0
	h.Write(counter)
	h.Write(dstBytesWithLength)
	b0 := h.Sum(nil) // b_0
	h.Reset()
	h.Write(b0)
	counter[0] = 1
	h.Write(counter)
	h.Write(dstBytesWithLength)
	bi := h.Sum(nil) // b_1
	out := append([]byte(nil), bi...)
	for len(out) < len_in_bytes {
		h.Reset()
		for j, x := range b0 {
			bi[j] ^= x
		}
		h.Write(bi)
		counter[0]++
		h.Write(counter)
		h.Write(dstBytesWithLength)
		bi = h.Sum(bi[:0]) // b_2, etc...
		out = append(out, bi...)
	}
	return out[:len_in_bytes]
}

// go:noinline
func secureClear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

///------
