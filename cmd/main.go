package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"

	"github.com/DragonF0rm/decent_6_shamir_scheme/keygen"
	"github.com/DragonF0rm/decent_6_shamir_scheme/shamir"
)

const (
	CMD_SPLIT   = "split"
	CMD_RECOVER = "recover"
	CMD_KEYGEN  = "keygen"
)

func handle_split() error {
	var prvKey []byte
	var N, T uint8

	if _, err := fmt.Scanf("0x%x\n%d %d", &prvKey, &N, &T); err != nil {
		return fmt.Errorf("fmt.Scanf: %w", err)
	}

	shares, err := shamir.Split(prvKey, N, T)
	if err != nil {
		return fmt.Errorf("shamir.Split: %w", err)
	}

	for _, share := range shares {
		fmt.Printf("0x%x\n", share.Marshal())
	}

	return nil
}

func handle_recover() error {
	var shares []*shamir.Share
	var rawShare []byte

	for {
		_, err := fmt.Scanf("0x%x\n", &rawShare)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}

			return fmt.Errorf("fmt.Scanf: %w", err)
		}

		share := &shamir.Share{}
		share.Unmarshal(rawShare)

		shares = append(shares, share)
	}

	prvKey, err := shamir.Recover(shares)
	if err != nil {
		return fmt.Errorf("shamir.Recover: %w", err)
	}

	fmt.Printf("0x%x\n", prvKey)

	return nil
}

func handle_keygen() error {
	prvKey, pubKey, err := keygen.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("keygen.GenerateKeypair: %w", err)
	}

	fmt.Printf("Private key:\t0x%x\n", prvKey)
	fmt.Printf("Public key:\t0x%x\n", pubKey)

	return nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: ./shamir %s|%s|%s", CMD_SPLIT, CMD_RECOVER, CMD_KEYGEN)
	}

	var handler func() error
	cmd := os.Args[1]

	switch cmd {
	case CMD_SPLIT:
		handler = handle_split
	case CMD_RECOVER:
		handler = handle_recover
	case CMD_KEYGEN:
		handler = handle_keygen
	default:
		log.Fatalf("Unknown command: %s. Usage: ./shamir %s|%s|%s",
			cmd, CMD_SPLIT, CMD_RECOVER, CMD_KEYGEN)
	}

	if err := handler(); err != nil {
		log.Fatalf("%v: %v\n",
			runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name(), err)
	}
}
