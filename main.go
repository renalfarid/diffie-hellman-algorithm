package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
)

func main() {

	/*
	  implement Elliptic Curve Diffie-Hellman (ECDH) algorithm
	  bob and alice want to send message each other, they agreed to use Elliptic Curve Diffie-Hellman (ECDH) algorithm.
	  so they will generate key, exchange key each other to make "secret key" that use to encrypt and decrypt the message.
	  the message that bob want to send is "Hello, secured world !"

	*/

	// alice generate key

	aliceCurve := ecdh.P256()
	alicePrivKey, err := aliceCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	alicePubKey := alicePrivKey.PublicKey() // now alice has pub key to exchange

	// bob generate key

	bobCurve := ecdh.P256()

	bobPrivKey, err := bobCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	bobPubKey := bobPrivKey.PublicKey() // now bob has pub key to exchange

	// now they will exchange key each other to make secret key (shared key)

	// alice secret key using bob pub key
	aliceSecret, err := alicePrivKey.ECDH(bobPubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	println("alice secret key: ", hex.EncodeToString(aliceSecret))

	// bob secret key using alice pub key
	bobSecret, err := bobPrivKey.ECDH(alicePubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	println("bob secret key: ", hex.EncodeToString(bobSecret))

	// now let compare alice secret key and bob secret key, are they match ?
	if !bytes.Equal(aliceSecret, bobSecret) {
		log.Fatalf("The secrets do not match")
	}
	log.Printf("The secrets match")

	// Now alice can use the secret secret to derive a symmetric key for encryption/decryption

	// Bob Encrypt a message using his secret key
	message := []byte("Hello, secure world!")
	encryptedMessage, err := encrypt(message, bobSecret)
	if err != nil {
		log.Fatalf("Error encrypting message: %v", err)
	}
	log.Printf("Bob Encrypted message: %v", hex.EncodeToString(encryptedMessage)) // bob send encrypt message

	// Alice Decrypt bob message using her secret key
	decryptedMessage, err := decrypt(encryptedMessage, aliceSecret)
	if err != nil {
		log.Fatalf("Error decrypting message: %v", err)
	}
	log.Printf("Alice Decrypted message: %v", string(decryptedMessage))

}

// Encrypt encrypts the plaintext using AES-GCM with the provided key.
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts the ciphertext using AES-GCM with the provided key.
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
