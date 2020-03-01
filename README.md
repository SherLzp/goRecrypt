# goRecrypt
`goRecrypt` is a tool to execute proxy re-encryption algorithms. It offers a high-level API to easily implement the process of re-encryption.

# Introduction and Theory

We assume that there have two users: $Alice$ and $Bob$ , $Alice$ wants to share something with $Bob$ through the $third\text{-}party$(Maybe the $Server$) . However, $Alice$ doesn't want $third\text{-}party$ to see her $plainText$ . So, one of the method now is $Proxy \ Re\text{-}Encryption$ ($PRE$).

## Prerequisites

We assume that $Alice$ and $Bob$ have already generate their own key-pairs(based on $P256 \ Curve$), $g$ is the generator of $Curve:G$ , $p$ is a big prime number and also is the order of the $G$. $H_i,i=2,3,4$ are hash  functions. $m$ is the `message` or `plaintext` what $Alice$ wants share. $Server$ is the $third\text{-}party $.
$$
sk \xleftarrow{R} \mathbb{Z}_p， pk = g^{sk} \\
Alice: sk_A,pk_A \\
Bob: sk_B,pk_B
$$

## Encrypt

$Alice$ executes: $\mathcal{G}$ is the $\Pi = \mathcal{E}_{AES},\mathcal{D}_{AES}$($AES$ encryption/decryption algorithm) key generator algorithm.

$Encrypt(m,pk_A)$:
$$
e,v \xleftarrow{R} \mathbb{Z}_P \\
E = g^{e},V=g^{v} \\
s = v + r \cdot H_2(E \| V) \\
K = \mathcal{G}((pk_A)^{e + v}) \\
m_{enc} = \mathcal{E}_{AES}(m,K) \\
capsule = (E,V,s)
$$
Then $Alice$ sends $m_{enc},capsule$ to the $Server$.

## ReKeyGen

$Alice$ executes:

$ReKeyGen(sk_A,pk_B)$
$$
x_A \xleftarrow{R} \mathbb{Z}_p,X_A = g^{x_A} \\
d = H_3(X_A \| pk_B \| pk_B^{x_A}) \\
rk = sk_A \cdot d^{-1}
$$
Then $Alice$ sends $rk,X_A$ to $Server$.

## ReEncryption

$Server$ executes:

$ReEncrption(rk,capsule)$:
$$
capsule = (E,V,s) \\
if \ g^s == \ V \cdot E^{H_2(E \| V)} \ then \\
E' = E^{rk}, V' = V^{rk} \\
capsule = (E',V',s) \\
end \ if
$$
Then $Server$ sends $X_A,capsule$ to $Bob$.

## ReCreateKey

$Bob$ executes:

$ReCreateKey(sk_B,capsule,m_{enc})$:
$$
d = H_3(X_A \| pk_B \| S^{sk_B}) \\
K = \mathcal{G}((E' \cdot V')^d)
$$

## Decrypt

$Bob$ executes:

$Decrypt(m_{enc},K)$:
$$
m = \mathcal{D}_{AES}(m_{enc},K)
$$

# Getting started

## Install

```sh
$ go get -v github.com/SherLzp/goRecrypt
```

## Test

