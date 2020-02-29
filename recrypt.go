package main

import (
	"crypto/ecdsa"
	"math/big"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	s *big.Int
}

func Encrypt(message string, pubKey *ecdsa.PublicKey) (cipherText []byte, capsule Capsule) {
	s := new(big.Int)
	priE, pubE := GenerateKeys()
	priV, pubV := GenerateKeys()
	h := HashToCurve(ConcatBytes(PointToBytes(pubE), PointToBytes(pubV)))
	s = BigIntAdd(priV.D, BigIntMul(priE.D, h))
	point := PointScalarMul(pubKey, BigIntAdd(priE.D, priV.D))
	key := Sha3Hash(PointToBytes(point))
	cipherText = AesCbcEncrypt([]byte(message), key[16:])
	capsule = Capsule{
		E: pubE,
		V: pubV,
		s: s,
	}
	return cipherText, capsule
}

func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, ecdsa.PublicKey) {
	priX, pubX := GenerateKeys()
	point := PointScalarMul(bPubKey, priX.D)
	d := HashToCurve(
		ConcatBytes(
			ConcatBytes(
				PointToBytes(pubX),
				PointToBytes(bPubKey)),
			PointToBytes(point)))
	rk := BigIntMul(aPriKey.D, GetInvert(d))
	rk.Mod(rk, N)
	return rk, *pubX
}

func ReEncryption(rk *big.Int, capsule Capsule) Capsule {
	capsule.E = PointScalarMul(capsule.E, rk)
	capsule.V = PointScalarMul(capsule.V, rk)
	return capsule
}

func RecreateKey(bPriKey *ecdsa.PrivateKey, capsule Capsule, pubX *ecdsa.PublicKey) []byte {
	S := PointScalarMul(pubX, bPriKey.D)
	d := HashToCurve(
		ConcatBytes(
			ConcatBytes(
				PointToBytes(pubX),
				PointToBytes(&bPriKey.PublicKey)),
			PointToBytes(S)))
	point := PointScalarMul(PointScalarAdd(capsule.E, capsule.V), d)
	key := Sha3Hash(PointToBytes(point))[16:]
	return key
}

func Decrypt(cipherText []byte, key []byte) []byte {
	plainText := AesCbcDecrypt(cipherText, key)
	return plainText
}
