package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const BIGINT_SIZE = 128

func bigintMarshal(n *big.Int) []byte {
	return n.FillBytes(make([]byte, BIGINT_SIZE))
}

func bigintUnmarshal(bytes []byte) *big.Int {
	return big.NewInt(0).SetBytes(bytes[:BIGINT_SIZE])
}

type Share struct {
	X uint8
	Y *big.Int
}

func (s *Share) Marshal() []byte {
	bytes := make([]byte, 0, BIGINT_SIZE+1)
	bytes = append(bytes, s.X)
	bytes = append(bytes, bigintMarshal(s.Y)...)

	return bytes
}

func (s *Share) Unmarshal(bytes []byte) {
	s.X = bytes[0]
	s.Y = bigintUnmarshal(bytes[1:])
}

var ErrInval = errors.New("Invalid args")

// Each coef belongs to [-RAND_COEF_RADIUS, RAND_COEF_RADIUS]
// The bigger RAND_COEF_RADIUS the harder it to brute force the shares
const RAND_COEF_RADIUS = math.MaxUint64

func Split(prvKey []byte, N, T uint8) ([]*Share, error) {
	if !(2 < T && T <= N && N < 100) {
		return nil, fmt.Errorf("%w: N=%d, T=%d. Must be: 2 < T <= N < 100",
			ErrInval, N, T)
	}

	coefs := make([]*big.Int, T)
	coefs[0] = big.NewInt(0).SetBytes(prvKey) // secret

	// maxRand := RAND_COEF_RADIUS * 2 + 1
	maxRand := big.NewInt(0).SetUint64(RAND_COEF_RADIUS)
	maxRand.Mul(maxRand, big.NewInt(2))
	maxRand.Add(maxRand, big.NewInt(1))

	for i := uint8(1); i < T; i++ {
		coef, err := rand.Int(rand.Reader, maxRand)
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}

		coefs[i] = coef.Sub(coef, big.NewInt(0).SetUint64(RAND_COEF_RADIUS))
	}

	shares := make([]*Share, N)

	// shares[i] = {x(i), y(x)}; i = 0..N; x(i) = i + 1
	for i := uint8(0); i < N; i++ {
		x := i + 1

		// y(x) = sum(coefs[j] * x^j); j = 0..T
		y := big.NewInt(0)
		for j := 0; j < len(coefs); j++ {
			term := int64(math.Pow(float64(x), float64(j)))
			y.Add(y, big.NewInt(0).Mul(coefs[j], big.NewInt(term)))
		}

		shares[i] = &Share{X: x, Y: y}
	}

	return shares, nil
}

// Lagrange's interpolation function
func interpolate(shares []*Share, x uint8) (y *big.Int) {
	newBigFloat := func(x float64) *big.Float {
		return big.NewFloat(x).SetPrec(BIGINT_SIZE * 8) // byte -> bit conv
	}

	f := newBigFloat(0)

	for i := 0; i < len(shares); i++ {
		term := newBigFloat(0).SetInt(shares[i].Y)

		for j := 0; j < len(shares); j++ {
			if i == j {
				continue
			}

			// term = term * (x - shares[j].X) / (shares[i].X - shares[j].X)
			term.Mul(term, newBigFloat(0).Sub(newBigFloat(float64(x)),
				newBigFloat(float64(shares[j].X))))
			term.Quo(term, newBigFloat(0).Sub(newBigFloat(float64(shares[i].X)),
				newBigFloat(float64(shares[j].X))))
		}

		f.Add(f, term)
	}

	y = big.NewInt(0)
	f.Int(y)

	return y
}

func Recover(shares []*Share) ([]byte, error) {
	secret := interpolate(shares, 0)
	return secret.Bytes(), nil
}
