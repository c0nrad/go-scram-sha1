package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"

	"crypto/hmac"
	"crypto/sha1"

	"code.google.com/p/go.crypto/pbkdf2"
)

const (
	ClientNonce     = "fyko+d2lbbFgONRv9qkxdawL"
	ServerNonce     = "3rfcNHYJY1ZVvWVs7j"
	ServerSalt      = "QSXCR+Q6sek8bf92"
	ServerStoredKey = "6dlGYMOdZcOPutkcNY8U2g7vK9Y="
	ServerServerKey = "D+CSWLOshSulAsxiupA+qs2/fTE="

	ClientName   = "user"
	ClientPass   = "pencil"
	ClientHeader = "biws"

	Iterations = 4096

	PBKDF2Length = 20
)

func pbkdf2Sum(password, salt []byte, i int) []byte {
	return pbkdf2.Key(password, salt, i, PBKDF2Length, sha1.New)
}

func hmacSum(key, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func sha1Sum(message []byte) []byte {
	mac := sha1.New()
	mac.Write(message)
	return mac.Sum(nil)
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		fmt.Println("Warning: xor lengths are differing...", a, b)
	}

	count := len(a)
	if len(b) < count {
		count = len(b)
	}

	out := make([]byte, count)
	for i := 0; i < count; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func toBase64(src []byte) []byte {
	out := base64.StdEncoding.EncodeToString(src)
	return []byte(out)
}

func fromBase64(src []byte) []byte {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	l, _ := base64.StdEncoding.Decode(dst, src)
	return dst[:l]
}

func normalize(in []byte) []byte {
	return in
}

func clientFirstMessageBare(cName, cNonce []byte) (out []byte) {
	out = []byte("n=")
	out = append(out, cName...)
	out = append(out, ",r="...)
	out = append(out, cNonce...)
	return
}

func clientFirstMessage(cName, cNonce []byte) (out []byte) {
	out = []byte("n,,")
	out = append(out, clientFirstMessageBare(cName, cNonce)...)
	return
}

func serverFirstMessage(sNonce, sSalt, cNonce, cName []byte, iterations int) (out []byte) {
	nonce := append(cNonce, sNonce...)

	out = append(out, "r="...)
	out = append(out, nonce...)
	out = append(out, ",s="...)
	out = append(out, sSalt...)
	out = append(out, ",i="...)
	out = append(out, strconv.Itoa(iterations)...)

	return
}

func clientFinalMessageWithoutProof(cHeader, cNonce, sNonce []byte) (out []byte) {
	nonce := append(cNonce, sNonce...)

	out = []byte("c=")
	out = append(out, cHeader...)
	out = append(out, ",r="...)
	out = append(out, nonce...)
	return
}

func authMessage(cName, cNonce, sNonce, sSalt, cHeader []byte, iterations int) (out []byte) {
	out = clientFirstMessageBare(cName, cNonce)
	out = append(out, ","...)
	out = append(out, serverFirstMessage(sNonce, sSalt, cNonce, cName, iterations)...)
	out = append(out, ","...)
	out = append(out, clientFinalMessageWithoutProof(cHeader, cNonce, sNonce)...)
	return
}

func clientFinalMessage(cName, cPass, cNonce, sNonce, sSalt, cHeader []byte, iterations int) (out []byte) {
	authMessage := authMessage(cName, cNonce, sNonce, sSalt, cHeader, iterations)

	saltedPassword := pbkdf2Sum(normalize(cPass), fromBase64(sSalt), iterations)

	clientKey := hmacSum(saltedPassword, []byte("Client Key"))
	storedKey := sha1Sum(clientKey)
	clientSignature := hmacSum(storedKey, authMessage)

	clientProof := xor(clientKey, clientSignature)

	out = clientFinalMessageWithoutProof(cHeader, cNonce, sNonce)
	out = append(out, ",p="...)
	out = append(out, toBase64(clientProof)...)

	return
}

func serverFinalMessage(sServerKey, cName, cNonce, sNonce, sSalt, cHeader []byte, iterations int) (out []byte) {
	authMessage := authMessage(cName, cNonce, sNonce, sSalt, cHeader, iterations)

	serverSignature := hmacSum(sServerKey, authMessage)

	out = []byte("v=")
	out = append(out, toBase64(serverSignature)...)
	return
}

func getAttribute(message []byte, attribute byte) []byte {
	attributes := bytes.Split(message, []byte{','})

	for _, a := range attributes {
		if len(a) > 0 && a[0] == attribute {
			return a[2:]
		}
	}
	return nil
}

func isValidClient(cName, cNonce, sNonce, sSalt, cHeader, sStoredKey, cProof []byte, iterations int) bool {
	authMessage := authMessage(cName, cNonce, sNonce, sSalt, cHeader, iterations)
	clientSignature := hmacSum(sStoredKey, authMessage)
	clientKey := xor(clientSignature, cProof)

	attemptingStoredKey := sha1Sum(clientKey)

	return bytes.Equal(attemptingStoredKey, sStoredKey)
}

func isValidServer(cName, cPass, cNonce, sNonce, sSalt, cHeader, serverSignature []byte, iterations int) bool {
	authMessage := authMessage(cName, cNonce, sNonce, sSalt, cHeader, iterations)

	saltedPassword := pbkdf2Sum(normalize(cPass), fromBase64(sSalt), iterations)
	serverKey := hmacSum(saltedPassword, []byte("Server Key"))

	attemptingServerSignature := hmacSum(serverKey, authMessage)

	return bytes.Equal(attemptingServerSignature, serverSignature)
}

func main() {

	// Client First Message
	cName := []byte(ClientName)
	cPass := []byte(ClientPass)
	cNonce := []byte(ClientNonce)
	cFirstMessage := clientFirstMessage(cName, cNonce)
	fmt.Printf("C: %s\n", cFirstMessage)

	cNonce = getAttribute(cFirstMessage, byte('r'))

	// Server First Message
	sNonce := []byte(ServerNonce)
	sSalt := []byte(ServerSalt)
	iterations := Iterations
	sFirstMessage := serverFirstMessage(sNonce, sSalt, cNonce, cName, iterations)
	fmt.Printf("S: %s\n", sFirstMessage)

	// Client Final Message
	cHeader := []byte(ClientHeader)
	cFinalMessage := clientFinalMessage(cName, cPass, cNonce, sNonce, sSalt, cHeader, iterations)
	fmt.Printf("C: %s\n", cFinalMessage)

	// Server Final Message
	sServerKey := fromBase64([]byte(ServerServerKey))
	sFinalMessage := serverFinalMessage(sServerKey, cName, cNonce, sNonce, sSalt, cHeader, iterations)
	fmt.Printf("S: %s\n", sFinalMessage)

	sStoredKey := fromBase64([]byte(ServerStoredKey))
	cProof := fromBase64(getAttribute(cFinalMessage, byte('p')))
	fmt.Println("Verified Client:", isValidClient(cName, cNonce, sNonce, sSalt, cHeader, sStoredKey, cProof, iterations))

	serverSignature := fromBase64(getAttribute(sFinalMessage, byte('v')))
	fmt.Println("Verified Server:", isValidServer(cName, cPass, cNonce, sNonce, sSalt, cHeader, serverSignature, iterations))

}
