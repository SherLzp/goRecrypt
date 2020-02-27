package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strings"
)

func GenerateKeyPair() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	privateKeyBytes, _ := x509.MarshalECPrivateKey(privateKey)
	privateKeyStr := hex.EncodeToString(privateKeyBytes)
	publicKeyStr := hex.EncodeToString(publicKeyBytes)
	return privateKeyStr, publicKeyStr, nil
}

func HashMessage(message string) (string) {
	shaInst := sha3.New256()
	shaInst.Write([]byte(message))
	result := shaInst.Sum(nil)
	return hex.EncodeToString(result)
}

func Sign(privateKeyStr string, messageHash string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return "", err
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, []byte(messageHash))
	if err != nil {
		return "", err
	}
	rStr, _ := r.MarshalText()
	sStr, _ := s.MarshalText()
	var result bytes.Buffer
	w := gzip.NewWriter(&result)
	defer w.Close()
	_, err = w.Write([]byte(string(rStr) + "+" + string(sStr)))
	if err != nil {
		return "", err
	}
	w.Flush()
	return hex.EncodeToString(result.Bytes()), nil
}

func Verify(messageHash, signature string, publicKey string) (bool, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, err
	}
	pubKey, _ := x509.ParsePKIXPublicKey(publicKeyBytes)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	reader, err := gzip.NewReader(bytes.NewBuffer(sigBytes))
	if err != nil {
		return false, err
	}
	defer reader.Close()
	buf := make([]byte, 1024)
	count, err := reader.Read(buf)
	if err != nil {
		return false, err
	}
	rsArr := strings.Split(string(buf[:count]), "+")
	if len(rsArr) != 2 {
		return false, err
	}
	var r, s big.Int
	err = r.UnmarshalText([]byte(rsArr[0]))
	if err != nil {
		return false, err
	}
	err = s.UnmarshalText([]byte(rsArr[1]))
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(pubKey.(*ecdsa.PublicKey), []byte(messageHash), &r, &s)
	return result, nil
}
