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
Message that bob want to send is "Hello, secured world !"