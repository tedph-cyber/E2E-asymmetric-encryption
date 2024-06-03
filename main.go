package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"net/http"
)

func loadPublicKeyFromString(pubKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return pubKey, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}

func loadPrivateKeyFromString(privKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func encryptMessage(message string, pubKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(message), nil)
}

func decryptMessage(cipherText []byte, privKey *rsa.PrivateKey) (string, error) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func main() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, nil)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		message := r.FormValue("message")
		publicKeyPEM := r.FormValue("publicKey")

		publicKey, err := loadPublicKeyFromString(publicKeyPEM)
		if err != nil {
			http.Error(w, "Invalid public key: "+err.Error(), http.StatusBadRequest)
			return
		}

		encryptedMessage, err := encryptMessage(message, publicKey)
		if err != nil {
			http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("encrypt.html"))
		tmpl.Execute(w, map[string]string{
			"Message":          message,
			"EncryptedMessage": fmt.Sprintf("%x", encryptedMessage),
		})
	}
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		encryptedMessageHex := r.FormValue("encryptedMessage")
		privateKeyPEM := r.FormValue("privateKey")

		encryptedMessage, err := hex.DecodeString(encryptedMessageHex)
		if err != nil {
			http.Error(w, "Invalid encrypted message: "+err.Error(), http.StatusBadRequest)
			return
		}

		privateKey, err := loadPrivateKeyFromString(privateKeyPEM)
		if err != nil {
			http.Error(w, "Invalid private key: "+err.Error(), http.StatusBadRequest)
			return
		}

		decryptedMessage, err := decryptMessage(encryptedMessage, privateKey)
		if err != nil {
			http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		tmpl := template.Must(template.ParseFiles("decrypt.html"))
		tmpl.Execute(w, map[string]string{
			"EncryptedMessage": encryptedMessageHex,
			"DecryptedMessage": decryptedMessage,
		})
	}
}
