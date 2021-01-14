package main

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/key"

	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
)

var (
	NumIterations = 5
)

func main() {
	dkgShares(5, 3)
}

func dkgShares(n, threshold int) {
	var priPoly *share.PriPoly
	var pubPoly *share.PubPoly
	var randomness []byte

	// create shares and commitments
	for i := 0; i < n; i++ {
		pri := share.NewPriPoly(key.KeyGroup, threshold, key.KeyGroup.Scalar().Pick(random.New()), random.New())
		pub := pri.Commit(key.KeyGroup.Point().Base())
		if priPoly == nil {
			priPoly = pri
			pubPoly = pub
			continue
		}
		priPoly, _ = priPoly.Add(pri)

		pubPoly, _ = pubPoly.Add(pub)
	}
	shares := priPoly.Shares(n)
	share.RecoverSecret(key.KeyGroup, shares, threshold, n)

	msg := []byte("initial seed")
	sigs := make([][]byte, n)
	_, commits := pubPoly.Info()
	dkgShares := make([]*key.Share, n)

	// partial signatures
	for i := 0; i < n; i++ {
		sigs[i], _ = key.Scheme.Sign(shares[i], msg)

		dkgShares[i] = &key.Share{
			Share:   shares[i],
			Commits: commits,
		}
	}

	f, err := os.Create("result.txt")
	defer f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	// reconstruct collective signature
	sig, _ := key.Scheme.Recover(pubPoly, msg, sigs, threshold, n)

	for j := 1; j <= NumIterations; j++ {

		msg = chain.Message(uint64(j), sig)
		sigs = make([][]byte, n)
		// partial signatures
		for i := 0; i < n; i++ {
			sigs[i], _ = key.Scheme.Sign(shares[i], msg)
		}

		// reconstruct collective signature
		newSig, _ := key.Scheme.Recover(pubPoly, msg, sigs, threshold, n)
		sig = newSig

		randomness, _ = ExtractRandomness(newSig)
		//log.Println(j, randomness)

		f.WriteString(fmt.Sprintf("%v\n", randomness))
		fmt.Printf("%v\n", randomness)
	}

}

// ExtractRandomness returns the randomness from a given signature.
func ExtractRandomness(signature []byte) ([]byte, error) {
	hash := sha512.New()
	if _, err := hash.Write(signature); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func Float64(r []byte) float64 {
	return float64(binary.BigEndian.Uint64(r[:8])>>11) / (1 << 53)
}
