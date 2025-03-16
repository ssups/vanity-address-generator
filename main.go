package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Key struct {
	Pk  *big.Int
	Pub *ecdsa.PublicKey
}

const (
	CASE_SENSITIVE  = false
	PREFIX          = "0x6666"
	SUFFIX          = "66"
	INIT_KEY_AMOUNT = 50
	GAP             = "0xffffffffffffffffffff"
)

func main() {
	start := time.Now()

	lowerPrefix := strings.ToLower(PREFIX)
	lowerSuffix := strings.ToLower(SUFFIX)

	initPk, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	seedKeys := make([]Key, INIT_KEY_AMOUNT)
	gap, err := hexutil.DecodeBig(GAP)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < INIT_KEY_AMOUNT; i++ {
		gapAddition := new(big.Int).Mul(big.NewInt(int64(i)), gap)
		seedPk := new(big.Int).Add(gapAddition, initPk.D)
		seedPk = new(big.Int).Mod(seedPk, secp256k1.S256().N)
		pkECDSA, err := crypto.ToECDSA(common.LeftPadBytes(seedPk.Bytes(), 32))
		if err != nil {
			continue
		}
		pubkey := pkECDSA.PublicKey
		seedKeys[i] = Key{
			Pk:  seedPk,
			Pub: &pubkey,
		}
	}

	fmt.Printf("SeedKeyMap initialized, len: %v\n", len(seedKeys))

	foundCh := make(chan struct{})
	monitorChan := make(chan struct{})
	bigOne := big.NewInt(1)
	gx := secp256k1.S256().Params().Gx
	gy := secp256k1.S256().Params().Gy

	for i, key := range seedKeys {
		go func(pub *ecdsa.PublicKey, pk *big.Int) {
			i := i
			j := big.NewInt(0)

			for {
				if i != (len(seedKeys)-1) && j.Cmp(gap) == 0 {
					fmt.Printf("go routine %v finished\n", i)
					return
				}
				select {
				case <-foundCh:
					return
				default:
					var found bool
					addr := crypto.PubkeyToAddress(*pub)
					if CASE_SENSITIVE {
						formattedAddr := addr.String()
						found = strings.HasPrefix(formattedAddr, PREFIX) && strings.HasSuffix(formattedAddr, SUFFIX)
					} else {
						formattedAddr := strings.ToLower(addr.String())
						found = strings.HasPrefix(formattedAddr, lowerPrefix) && strings.HasSuffix(formattedAddr, lowerSuffix)
					}
					if found {
						foundPkBig := new(big.Int).Mod(new(big.Int).Add(pk, j), secp256k1.S256().N)
						foundPk := hexutil.EncodeBig(foundPkBig)
						fmt.Printf("found address: %s\n", addr)
						fmt.Printf("pk: %s\n", foundPk)
						close(foundCh)
						return
					}
					pub.X, pub.Y = secp256k1.S256().Add(
						pub.X, pub.Y,
						gx, gy,
					)
					j.Add(j, bigOne)
					monitorChan <- struct{}{}
				}
			}

		}(key.Pub, key.Pk)
	}

	go func() {
		total := 0
		for {
			select {
			case <-monitorChan:
				total++
				if total%1000000 == 0 {
					fmt.Printf("searched %v account\n", total)
				}
			case <-foundCh:
				return
			}
		}
	}()

	<-foundCh
	elaps := time.Since(start)
	fmt.Printf("Took %v\n", elaps)
}
