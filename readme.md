# Implement Elliptic Curve Diffie-Hellman (ECDH) Algorithm
Bob and Alice want to send message each other, they agreed to use Elliptic Curve Diffie-Hellman (ECDH) algorithm.

```sh

	aliceCurve := ecdh.P256()
	alicePrivKey, err := aliceCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	alicePubKey := alicePrivKey.PublicKey() // now alice has pub key to exchange

```
```sh

	bobCurve := ecdh.P256()

	bobPrivKey, err := bobCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	bobPubKey := bobPrivKey.PublicKey() // now bob has pub key to exchange

```
so they will generate key, exchange key each other to make "secret key" that use to encrypt and decrypt the message.

```sh

	// alice secret key using bob pub key
	aliceSecret, err := alicePrivKey.ECDH(bobPubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	println("alice secret key: ", hex.EncodeToString(aliceSecret))

```

```sh

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

```

Message that bob want to send is "Hello, secured world !"