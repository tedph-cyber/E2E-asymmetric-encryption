package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	return pem.Encode(outFile, &privBlock)
}

func savePublicPEMKey(fileName string, pubkey *rsa.PublicKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}
	pubBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return pem.Encode(outFile, &pubBlock)
}

func main() {
	privateKey, publicKey, err := generateKeyPair(2048)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = savePEMKey("private.pem", privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = savePublicPEMKey("public.pem", publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Keys generated and saved.")
}
