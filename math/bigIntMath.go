package math

import (
	"github.com/SherLzp/goRecrypt/curve"
	"math/big"
)

func BigIntAdd(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Add(a, b)
	res.Mod(res, curve.N)
	return
}

func BigIntSub(a, b *big.Int) (res *big.Int) {
	res = new(big.Int)
	res.Sub(a, b)
	res.Mod(res, curve.N)
	return
}

func BigIntMul(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Mul(a, b)
	res.Mod(res, curve.N)
	return
}

func GetInvert(a *big.Int) (res *big.Int) {
	res = new(big.Int).ModInverse(a, curve.N)
	return
}
