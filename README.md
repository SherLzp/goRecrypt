# goRecrypt
`goRecrypt` is a tool to execute proxy re-encryption algorithms. It offers a high-level API to easily implement the process of re-encryption.

# Introduction and Theory

![1](assets/1.png)

## Prerequisites

![2](assets/2.png)

## Encrypt

![3](assets/3.png)

## ReKeyGen

![4](assets/4.png)

## ReEncryption

![5](assets/5.png)

## ReCreateKey

![6](assets/6.png)

## Decrypt

![7](assets/7.png)

# Getting started

## Install

```sh
$ go get -v github.com/SherLzp/goRecrypt
```

## Test

### Code

```go
package main

import (
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/recrypt"
)

func main() {
	// Alice Generate Alice key-pair
	aPriKey, aPubKey, _ := curve.GenerateKeys()
	// Bob Generate Bob key-pair
	bPriKey, bPubKey, _ := curve.GenerateKeys()
	// plain text
	m := "Hello, Proxy Re-Encryption"
	fmt.Println("origin message:", m)
	// Alice encrypts to get cipherText and capsule
	cipherText, capsule, err := recrypt.Encrypt(m, aPubKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ciphereText:", cipherText)
	// Alice generates re-encryption key
	rk, pubX, err := recrypt.ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("rk:", rk)
	// Server executes re-encrypt
	newCapsule, err := recrypt.ReEncryption(rk, capsule)
	if err != nil {
		fmt.Println(err.Error())
	}
	// Bob decrypts the cipherText
	plainText, err := recrypt.Decrypt(bPriKey, newCapsule, pubX, cipherText)
	if err != nil {
		fmt.Println(err)
	}
	// get plainText
	fmt.Println("plainText:", string(plainText))
}
```

### Result

```go
origin message: Hello, Proxy Re-Encryption
ciphereText: 384896d3ec76ae15b76195154e20ef069d5984d1bbac436d30df928af043106f09b08d50ef7562bf44fa
rk: 63105820755377318789444476285016130489439585789958062421755769345359288283133
plainText: Hello, Proxy Re-Encryption
```

Thanks! 