package opaque

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"math/big"
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
	Blind(input []byte) (blind, blindedElement []byte)
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

const Noe = 0  //size of serialized element
const Nok = 32 //size of OPRF private key

type ClientState struct {
	// oprf state
	password []byte
	blind    []byte
	// AKE state
	clientSecret []byte
	ke1          KE1
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
	authResponse, err := s.AuthServerRespond(credentials, pubKey, clientRegRecord.pubKey, ke1, response)
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
	var oprf BlindSigner
	blind, blindElement := oprf.Blind(password)
	blindMessage := SerializeElement(blindElement)
	return &CredentialRequest{blindMessage}, blind
}

func newRandomNonce() []byte     { b := make([]byte, Nn); rand.Read(b); return b }
func newRandomSeed() [Nseed]byte { var b [Nseed]byte; rand.Read(b[:]); return b }

func CreateCredentialResponse(request *CredentialRequest, pubKey []byte, clientRegRecord *ClientRegRecord, credID, oprfSeed []byte) (*CredentialResponse, error) {
	var prfInfo = concats(credID, "OprfKey")
	r := hkdf.Expand(NewHash, oprfSeed, prfInfo)
	var seed [Nok]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		panic("hkdf failure")
	}

	oprfKey, _, err := DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
	if err != nil {
		return nil, err
	}
	blindedElement, err := DeserializeElement(request.blindedMessage)
	if err != nil {
		return nil, err
	}
	var oprf BlindEvaluator // TODO
	evaluatedElement, err := oprf.BlindEvaluate(oprfKey, blindedElement)
	if err != nil {
		return nil, err
	}
	evaluatedMessage := SerializeElement(evaluatedElement)

	maskingNonce := newRandomNonce()

	var maskingInfo = concats(maskingNonce, "CredentialResponsePad")
	r = hkdf.Expand(NewHash, clientRegRecord.maskingKey, maskingInfo)
	var xorpad = make([]byte, Npk+Nn+Nm)
	if _, err := io.ReadFull(r, xorpad); err != nil {
		panic("hkdf failure")
	}
	var maskedResponse []byte
	maskedResponse = append(maskedResponse, pubKey...) // server public key
	maskedResponse = append(maskedResponse, clientRegRecord.envelope...)
	for i, x := range xorpad {
		maskedResponse[i] ^= x
	}

	return &CredentialResponse{
		evaluatedMessage, maskingNonce, maskedResponse,
	}, nil
}

const (
	Npk = 0
	Nn  = 0
	Nm  = sha256.Size
)

func RecoverCredentials(password []byte, blind []byte, response *CredentialResponse, serverID, clientID []byte) (privKey []byte, credentials *CleartextCredentials, exportKey []byte, err error) {
	var oprf BlindSigner
	oprfOutput, err := oprf.Finalize(password, blind, response.evaluatedMessage)
	if err != nil {
		return nil, nil, nil, err
	}
	stretchedOutput, err := Stretch(oprfOutput)
	if err != nil {
		return nil, nil, nil, err
	}
	kdfInfo := append(oprfOutput, stretchedOutput...)
	randomizedPassword := hkdf.Extract(NewHash, nil, kdfInfo)

	r := hkdf.Expand(NewHash, randomizedPassword, []byte("MaskingKey"))
	var maskingKey = make([]byte, Nh)
	if _, err := io.ReadFull(r, maskingKey); err != nil {
		panic("hkdf error")
	}

	var maskingInfo = concats(response.maskingNonce, "CredentialResponsePad")
	r = hkdf.Expand(NewHash, maskingKey, maskingInfo)
	var xorpad = make([]byte, Npk+Nn+Nm)
	if _, err := io.ReadFull(r, xorpad); err != nil {
		panic("hkdf failure")
	}
	var unmaskedResponse = make([]byte, len(response.maskedResponse))
	for i, x := range xorpad {
		unmaskedResponse[i] = response.maskedResponse[i] ^ x
	}

	pubKey := unmaskedResponse[:Npk:Npk]
	envelope := unmaskedResponse[Npk:]

	clientKey, credentials, exportKey, err := Recover(randomizedPassword, pubKey, envelope, serverID, clientID)
	if err != nil {
		return nil, nil, nil, err
	}
	return clientKey, credentials, exportKey, nil
}

func concats(a []byte, b string) []byte {
	var out []byte
	out = append(out, a...)
	out = append(out, b...)
	return out
}

var EnvelopeRecoveryError = errors.New("opaque: failed to recover envelope")

const Nh = 0
const Nseed = 32

func Recover(randomizedPassword, pubKey, envelope, serverID, clientID []byte) (privKey []byte, credentials *CleartextCredentials, exportKey []byte, err error) {
	var authKey = make([]byte, Nh)
	exportKey = make([]byte, Nh)
	var seed [Nseed]byte
	envelopeNonce := envelope[0:Nn]
	envelopeAuthTag := envelope[Nn:Nm]
	r := hkdf.Expand(NewHash, randomizedPassword, concats(envelopeNonce, "AuthKey"))
	if _, err := io.ReadFull(r, authKey); err != nil {
		panic("hkdf failure: authKey")
	}
	r = hkdf.Expand(NewHash, randomizedPassword, concats(envelopeNonce, "ExportKey"))
	if _, err := io.ReadFull(r, exportKey); err != nil {
		panic("hkdf failure: exportKey")
	}
	r = hkdf.Expand(NewHash, randomizedPassword, concats(envelopeNonce, "PrivateKey"))
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		panic("hkdf failure: privateKey")
	}

	//clientPrivKey, clientPubKey := DeriveDiffieHellmanKeyPair(seed)
	clientPrivKey, clientPubKey, err := DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return nil, nil, nil, err
	}
	credentials = CreateCleartextCredentials(pubKey, clientPubKey, serverID, clientID)
	h := hmac.New(NewHash, authKey)
	h.Write(envelopeNonce)
	h.Write(credentials.serverPubKey)
	h.Write(credentials.serverID)
	h.Write(credentials.clientID)
	tag := h.Sum(nil)
	if !hmac.Equal(envelopeAuthTag, tag) {
		secureClear(credentials.serverPubKey)
		secureClear(credentials.serverID)
		secureClear(credentials.clientID)
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
	clientSecret, clientPubKeyshare, err := DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return KE1{}, err
	}
	c.clientSecret = clientSecret
	c.ke1 = KE1{request, AuthRequest{nonce, clientPubKeyshare}}
	return c.ke1, nil
}

func (s *ServerState) AuthServerRespond(creds *CleartextCredentials, privKey []byte, clientPubKey []byte, ke1 KE1, credResponse *CredentialResponse) (*AuthResponse, error) {
	serverNonce := newRandomNonce()
	seed := newRandomSeed()
	// DeriveDiffieHellmanKeyPair
	serverPrivKeyshare, serverPubKeyshare, err := DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
	if err != nil {
		return nil, err
	}
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
	dh1 := DiffieHellman(c.clientSecret, ke2.authResponse.serverPubKeyshare)
	dh2 := DiffieHellman(c.clientSecret, creds.serverPubKey)
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
	if !hmac.Equal(expectedTag, km3) {
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
	h := NewHash()
	h.Write([]byte("OPAQUEv1-"))
	h.Write([]byte{byte(len(applicationContext) >> 8), byte(len(applicationContext))})
	h.Write(applicationContext)
	h.Write([]byte{byte(len(clientID) >> 8), byte(len(clientID))})
	h.Write(clientID)
	h.Write(ke1.credentialRequest.blindedMessage)
	h.Write([]byte{byte(len(serverID) >> 8), byte(len(serverID))})
	h.Write(serverID)
	h.Write(ke2.credentialResponse.evaluatedMessage)
	h.Write(ke2.credentialResponse.maskingNonce)
	h.Write(ke2.credentialResponse.maskedResponse)
	h.Write(ke2.authResponse.serverNonce)
	h.Write(ke2.authResponse.serverPubKeyshare)
	return h
}

func DiffieHellman(privKey, pubKey []byte) []byte {
	p, err := nistec.NewP256Point().SetBytes(pubKey)
	if err != nil {
		panic(err)
	}
	p.ScalarMult(p, pubKey)
	return p.BytesCompressed()
}

func DeriveKeys(ikm, preambleHash []byte) (km2, km3, sessionKey []byte) {
	prk := hkdf.Extract(NewHash, ikm, nil)
	handshakeSecret := DeriveSecret(prk, "HandshakeSecret", preambleHash)
	sessionKey = DeriveSecret(prk, "SessionKey", preambleHash)
	km2 = DeriveSecret(handshakeSecret, "ServerMAC", nil)
	km3 = DeriveSecret(handshakeSecret, "ClientMAC", nil)
	return km2, km3, sessionKey
}

func DeriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	h := hmac.New(NewHash, secret)
	Nx := h.Size()
	h.Write([]byte{byte(Nx >> 8), byte(Nx)})
	h.Write([]byte("OPAQUE-" + label))
	h.Write(transcriptHash)
	return h.Sum(nil)
}

// Deterministic key generation from RFC9497
//
// OPRF(P-256, SHA-256)
// https://www.rfc-editor.org/rfc/rfc9497.html#name-oprfp-256-sha-256
//

var DeriveKeyPairError = errors.New("failed to derive key pair")

const contextString = "OPRFV1-\x00-OPAQUE-POC"

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
