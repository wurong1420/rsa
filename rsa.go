package handler

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"math/big"
)

func decrypt(priKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	d, n := priKey.D.String(), priKey.N.String()
	c := new(big.Int).SetBytes(ciphertext)

	privateExponent := new(big.Int)
	modulus := new(big.Int)

	if _, ok := privateExponent.SetString(d, 10); !ok {
		return nil, rsa.ErrDecryption
	}
	if _, ok := modulus.SetString(n, 10); !ok {
		return nil, errors.New("failed to parse modulus")
	}

	//m = c^d mod n
	m := new(big.Int).Exp(c, privateExponent, modulus)

	return m.Bytes(), nil
}

func encrypt(pubKey *rsa.PublicKey, signature []byte) []byte {
	signatureInt := new(big.Int).SetBytes(signature)

	//m = s^e mod n
	decryptedInt := new(big.Int).Exp(signatureInt, big.NewInt(int64(pubKey.E)), pubKey.N)

	decryptedBytes := decryptedInt.Bytes()

	//fill 0
	keySize := (pubKey.N.BitLen() + 7) / 8
	if len(decryptedBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(decryptedBytes):], decryptedBytes)
		decryptedBytes = padded
	}
	return decryptedBytes
}

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
	crypto.SHA3_224:  {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA3_256:  {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_384:  {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA3_512:  {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
}

func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

func SignPKCS1v15(priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := priv.Size()
	if k < tLen+11 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	return decrypt(priv, em)
}

func VerifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return err
	}

	tLen := len(prefix) + hashLen
	k := pub.Size()
	if k < tLen+11 {
		return rsa.ErrVerification
	}

	// RFC 8017 Section 8.2.2: If the length of the signature S is not k
	// octets (where k is the length in octets of the RSA modulus n), output
	// "invalid signature" and stop.
	if k != len(sig) {
		return rsa.ErrVerification
	}

	em := encrypt(pub, sig)
	ok := subtle.ConstantTimeByteEq(em[0], 0)
	ok &= subtle.ConstantTimeByteEq(em[1], 1)
	ok &= subtle.ConstantTimeCompare(em[k-hashLen:k], hashed)
	ok &= subtle.ConstantTimeCompare(em[k-tLen:k-hashLen], prefix)
	ok &= subtle.ConstantTimeByteEq(em[k-tLen-1], 0)

	for i := 2; i < k-tLen-1; i++ {
		ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
	}

	if ok != 1 {
		return rsa.ErrVerification
	}

	return nil
}
