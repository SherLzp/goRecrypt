package main

import (
	"fmt"
	"goRecrypt/goRecrypt"
)

func main() {
	aPriKey, aPubKey := goRecrypt.GenerateKeys()
	bPriKey, bPubKey := goRecrypt.GenerateKeys()
	cipherText, capsule := goRecrypt.Encrypt("Hello", aPubKey)
	fmt.Println("ciphereText:", cipherText)
	rk, pubX := goRecrypt.ReKeyGen(aPriKey, bPubKey)
	newCapsule := goRecrypt.ReEncryption(rk, capsule)
	key := goRecrypt.RecreateKey(bPriKey, newCapsule, &pubX)
	plainText := goRecrypt.Decrypt(cipherText, key)
	fmt.Println("plainText:", string(plainText))
}
