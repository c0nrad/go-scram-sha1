package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func fromHex(src []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(dst, src)
	return dst
}

func TestPBKDF2Sum(t *testing.T) {
	password := []byte("pencil")
	iterations := 4096
	salt := fromBase64([]byte("QSXCR+Q6sek8bf92"))
	out := pbkdf2Sum(password, salt, iterations)
	sln := fromBase64([]byte("HZbuOlKbWl+eR8AfIposuKbhX30="))

	if !bytes.Equal(out, sln) {
		t.Error("Failed to generate correct PBKDF2 for scram")
	}
}

func TestHMAC(t *testing.T) {
	saltedPassword := []byte("HZbuOlKbWl+eR8AfIposuKbhX30=")
	out := hmacSum(fromBase64(saltedPassword), []byte("Client Key"))

	sln := []byte("4jTEe/bDZpbdbYUrmaqiuiZVVyg=")

	if !bytes.Equal(toBase64(out), sln) {
		t.Error("Failed to generate correct hmac")
	}
}

func TestHMACWiki(t *testing.T) {
	// HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = 0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
	message := []byte("The quick brown fox jumps over the lazy dog")
	key := []byte("key")
	sln := fromHex([]byte("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"))

	out := hmacSum(key, message)
	if !bytes.Equal(out, sln) {
		fmt.Println("Failed to take correct hmac")
	}

}
