package recrypt

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/math"
	"goRecrypt/utils"
	"math/big"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	s *big.Int
}

// Encrypt the message
// AES GCM + Proxy Re-Encryption
func Encrypt(message string, pubKey *ecdsa.PublicKey) (cipherText string, capsule *Capsule, err error) {
	s := new(big.Int)
	// generate E,V key-pairs
	priE, pubE, err := curve.GenerateKeys()
	priV, pubV, err := curve.GenerateKeys()
	if err != nil {
		return "", nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// get s = v + e * H2(E || V)
	s = math.BigIntAdd(priV.D, math.BigIntMul(priE.D, h))
	// get (pk_A)^{e+v}
	point := curve.PointScalarMul(pubKey, math.BigIntAdd(priE.D, priV.D))
	// generate aes key
	hash, err := utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return "", nil, err
	}
	key := hex.EncodeToString(hash)
	fmt.Println("old key:", key)
	// use aes gcm algorithm to encrypt
	// mark hash[:12] as nonce
	cipherText, err = GCMEncrypt(message, key[:32], hash[:12], nil)
	if err != nil {
		return "", nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		s: s,
	}
	return cipherText, capsule, nil
}

func EncryptByStr(message, pubKeyStr string) (cipherText string, capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return "", nil, err
	}
	return Encrypt(message, key)
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	// generate x,X key-pair
	priX, pubX, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get d = H3(X_A || pk_B || pk_B^{x_A})
	point := curve.PointScalarMul(bPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(point)))
	// rk = sk_A * d^{-1}
	rk := math.BigIntMul(aPriKey.D, math.GetInvert(d))
	rk.Mod(rk, curve.N)
	return rk, pubX, nil
}

func ReKeyGenByStr(aPriKeyStr, bPubKeyStr string) (*big.Int, *ecdsa.PublicKey, error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := utils.PublicKeyStrToKey(bPubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return ReKeyGen(aPriKey, bPubKey)
}

// Server executes Re-Encryption method
func ReEncryption(rk *big.Int, capsule *Capsule) (*Capsule, error) {
	// check g^s == V * E^{H2(E || V)}
	x1, y1 := curve.CURVE.ScalarBaseMult(capsule.s.Bytes())
	tempX, tempY := curve.CURVE.ScalarMult(capsule.E.X, capsule.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(capsule.E),
				curve.PointToBytes(capsule.V))).Bytes())
	x2, y2 := curve.CURVE.Add(capsule.V.X, capsule.V.Y, tempX, tempY)
	// if check failed return error
	if x1.Cmp(x2) != 0 && y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}
	// E' = E^{rk}, V' = V^{rk}
	newCapsule := &Capsule{
		E: curve.PointScalarMul(capsule.E, rk),
		V: curve.PointScalarMul(capsule.V, rk),
		s: capsule.s,
	}
	return newCapsule, nil
}

// Recreate the aes key then decrypt the cipherText
func Decrypt(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey, cipherText string) (string, error) {
	// S = X_A^{sk_B}
	S := curve.PointScalarMul(pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(capsule.E, capsule.V), d)
	hash, err := utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return "", err
	}
	// recreate aes key = G((E' * V')^d)
	key := hex.EncodeToString(hash)
	// use aes gcm to decrypt
	// mark hash[:12] as nonce
	plainText, err := GCMDecrypt(cipherText, key[:32], hash[:12], nil)
	if err != nil {
		return "", err
	}
	return plainText, nil
}

func DecryptByStr(bPriKeyStr string, capsule *Capsule, pubXStr string, cipherText string) (string, error) {
	bPriKey, err := utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return "", err
	}
	pubX, err := utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return "", err
	}
	return Decrypt(bPriKey, capsule, pubX, cipherText)
}

// Decrypt by my own private key
func DecryptOnMyPriKey(aPriKey *ecdsa.PrivateKey, capsule *Capsule, cipherText string) (string, error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point := curve.PointScalarMul(point1, aPriKey.D)
	// generate aes key
	hash, err := utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return "", err
	}
	key := hex.EncodeToString(hash)
	fmt.Println("new key:", key)
	// use aes gcm algorithm to encrypt
	// mark hash[:12] as nonce
	plainText, err := GCMDecrypt(cipherText, key[:32], hash[:12], nil)
	return plainText, err
}

func DecryptOnMyOwnStrKey(aPriKeyStr string, capsule *Capsule, cipherText string) (string, error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return "", err
	}
	return DecryptOnMyPriKey(aPriKey, capsule, cipherText)
}
