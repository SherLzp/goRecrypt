package goRecrypt

import "math/big"

func BigIntAdd(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Add(a, b)
	res.Mod(res, N)
	return
}

func BigIntSub(a, b *big.Int) (res *big.Int) {
	res = new(big.Int)
	res.Sub(a, b)
	res.Mod(res, N)
	return
}

func BigIntMul(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Mul(a, b)
	res.Mod(res, N)
	return
}

func GetInvert(a *big.Int) (res *big.Int) {
	res = new(big.Int).ModInverse(a, N)
	return
}
