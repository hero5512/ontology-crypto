package sm2

import "crypto/elliptic"
import "math/big"

// SM2Curve is the curve structure used in sm2 algorithm.
// It extends elliptic.CurveParams by adding the curve parameter A.
type SM2Curve struct {
	elliptic.CurveParams
	A *big.Int
}

var p256 *SM2Curve = nil

// SM2P256V1 returns the sm2p256v1 curve.
func SM2P256V1() elliptic.Curve {
	if p256 == nil {
		p256 = &SM2Curve{
			CurveParams: elliptic.CurveParams{
				Name: "sm2p256v1",
			},
		}
		//p256 = &elliptic.CurveParams{Name: "SM2-P-256"}
		p256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
		p256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
		p256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
		p256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
		p256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
		p256.BitSize = 256
		p256.A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	}

	return p256
}