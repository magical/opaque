var oprfContextString = "OPRFV1-\x00-"

// TODO: Applications MUST check that input Element values received over the wire are not the group identity element. This check is handled after deserializing Element values; see Section 4 for more information and requirements on input validation for each ciphersuite.

func randomScalar() []byte {
	//  4.7.2. Random Number Generation Using Extra Random Bits
	// Generate a random byte array with L = ceil(((3 * ceil(log2(G.Order()))) / 2) / 8) bytes, and interpret it as an integer; reduce the integer modulo G.Order(), and return the result. See [RFC9380], Section 5 for the underlying derivation of L.
	L := (256+128)/8
	var buf = make([]byte, L)
	if _, err := rand.Read(L); err != nil {
		panic("entropy failure")
	}
	e := new(big.Int).SetBytes(buf) // big endian
	// TODO: constant time?
	e.Mod(e, p256Order)
	// TODO: left pad with zeros?
	return e.Bytes()
}

func BlindP256(input []byte) {
	blind := randomScalar()


func hashToGroupP256(msg []byte) {
	// Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO_ [RFC9380] and DST = "HashToGroup-" || contextString

// Steps:
// 1. u = hash_to_field(msg, 2)
// 2. Q0 = map_to_curve(u[0])
// 3. Q1 = map_to_curve(u[1])
// 4. R = Q0 + Q1              # Point addition
// 5. P = clear_cofactor(R)
// 6. return P

	const L = 48 // (256 + 128) / 8
	uniform_bytes := expand_message_xmd(msg, DST, L+L)
	u0 := new(big.Int).SetBytes(uniform_bytes[0:L]) // big endian
	u1 := new(big.Int).SetBytes(uniform_bytes[L:]) // big endian
	// reduce scalar tv modulo the order of P-256
	// TODO: constant time?
	u0.Mod(u0, p256Order)
	u1.Mod(u1, p256Order)
	

}

var B, _ = new(big.Int).SetString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 0)

func mapToCurveSimpleSWU(u []byte) {
// Simplified Shallue-van de Woestijne-Ulas Method
	q := new(big.Int).Add(p256Order, big.NewInt(-2))

	inv0 := func(z *big.Int) { if z.Sign != 0 { return z.Exp(z, q, p256Order) } else { return z } }
	mod := func(z *big.Int) { return z.Mod(z, p256Order) }

	//1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
	Z := big.NewInt(-10)
	Z = Z.Add(Z, p256Order)
	Z2 := mod(Z.Mul(Z, Z))
	u2 := mod(new(big.Int).Mul(u, u))
	Zu2 := mod(new(big.Int).Mul(Z, u2))
	Z2u4 := mod(new(big.Int).Mul(Zu2, Zu2))
	tv1 := inv0(new(big.Int).Add(Z2u4, Zu2))
	//2.  x1 = (-B / A) * (1 + tv1)
	//3.  If tv1 == 0, set x1 = B / (Z * A)
	A := 3
	var x1 *big.Int
	if tv1.Sign() != 0 {
		x1 = mod(new(big.Int).Mul(B, inv0(big.NewInt(A))))
		x1 = x1.Sub(p256Order, x1)
		x1 = mod(x1.Mul(x1, new(big.Int).Add(tv1, big.NewInt(1))))
	} else {
		x1 = mod(inv0(new(big.Int).Mul(Z, big.NewInt(A))))
		x1 = mod(x1.Mul(x1, B))
	}
	//4. gx1 = x1^3 + A * x1 + B
	x1_cube := new(big.Int)
	x1_cube :=mod(x1_cube.Mul(x1, x1))
	x1_cube := mod(x1_cube.Mul(x1_cube, x1))
	Ax1 := mod(new(big.Int).Mul(x1, big.NewInt(A)))
	gx1 := new(big.Int)
	gx1 = gx1.Add(x1_cube, Ax1)
	gx1 = mod(gx1.Add(gx1, B))
	//5.  x2 = Z * u^2 * x1
	x2 := mod(new(big.Int).Mul(Z, u2))
	x2 = mod(x2.Mul(x2, x1))
	//6. gx2 = x2^3 + A * x2 + B
	x2_cube := new(big.Int)
	x2_cube = mod(x2_cube.Mul(x2, x2))
	x2_cube = mod(x2_cube.Mul(x2_cube, x2))
	Ax2 := mod(new(big.Int).Mul(x1, big.NewInt(A)))
	gx2 = gx2.Add(x2_cube, Ax2)
	gx2 = mod(gx2.Add(gx2, B))
	//7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
	//8.  Else set x = x2 and y = sqrt(gx2)
	x := new(big.Int)
	y := new(big.Int)
	if isSquare(gx1) {
		
	//9.  If sgn0(u) != sgn0(y), set y = -y
	//10. return (x, y)
}

func inv0(x) { return x^(q-2) }
