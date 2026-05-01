package main

import "math/big"

func bytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
