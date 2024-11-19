package handler

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"testing"

	"golang.org/x/crypto/sha3"
)

var (
	privateKeyStr = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3vGbrBGp6IQpL
8RtNFsCkp+ghke1MBm/4sn+KjLEoDirb9uUbSxcnyf8FiiN6IRGm+4QlhvXnMyWX
lq+tQErj8NNkF2xqwsRy1czwEe5LDulql2auwZWRK+hhlbroSVWEPYQiITEGZCPq
P4/kcTPy10hJMpSoWgkO+nUh3joVczaAjpqPiEFUKhVzwko+AtfUe75PC8fjNR6g
GegbcwI8ZfK00P+MVJlF27ihGAlTq+vCNxmaplvouQx+8A0l8cFNoQjZLA+G18yC
zddnTklOnsLu++xabR4z32Y/Yhy3pDnADZXIpJTLZWZH84Sn9MWtzjJ556IkFXyT
J1o5JVpZAgMBAAECggEAGDzSQXkjqANpHaYrY8/3OcFXQ0EXfJ/yGsHxRpBTY7ql
YhRVGh9IaVyhjP7cDzsC3nREym6IodHYHlcnyu21nhF20WKwT/psJSSZvvxJOGg5
18XWgIHTqS2Rn3iRCh4ibyoY9CeiFVBrLHZAv8dEgxRt2g9swjNJCUt2Mtw4l/uR
m+gOCjekhT5dhZjRJyS+2GUpihSdLcgw3mxbi6wy1OmV6vThbETQ98Ll37072sVG
kbhaOzmWIQnde5TzreDTvkSvjngua1KyKv8y544kZ/IBkRpYTw656JV6r4EHr7lq
AViU1w23XhwjUn11OiEtJlO9COiHT6NGUsqWi/QewQKBgQDfOPRlt2iXdO1g0cHp
03WW0abc3IjLuBWMT/N64Z2FKp071p2+l5Appz5RI7a0mFsfeFNuFZj1Qf8lz8LG
lBWT4ubjg2WhC6TS2CK7fKtuveOClg4utyfyv94ZICd75dfastkFPKj/M7JUzybT
owKzfjUxhp8jl5YEjBfBT4A8PwKBgQDStyDwjWntPcAE5oMZMTUcdOTuk+OUVt46
yJKgoVzgX26w4+G2a4Bzgtz2BRsGovYbrUHqHGQ4iarxGqc3pAvSyyEFVyARhCr+
yeXDHpAuFiXi65sul9lbFrAwEuEvuKfCiv8o9RYpsadW17DTYXWRGFsnlXe1RAMA
7cP9UY+jZwKBgFG2EZCiYMEAZlyIrAkiBOted0xl1hVsn0arhZ83s2epv8DFwRyh
cn4s4FznS9wz4TdV3oRvl3w/2lxG/y+dyYBHEOm7kZowHvencp9a9Y4mKIAG2c4z
8YWkwnJEGO/7pNZDnbmTCPHSRLdS1Q2noDeAPYyRkPOAa8PiXFfA+FoVAoGAeaxb
LexKdT6J6Yp9uwdKBtOM+iKVcCu1CTaWTIDA06LnlOcRh7eNpaW0F6+dCnkBKbwi
6p9YU7lS5wQf+KYWWbMHr0C++L5b4WIN9VxpnuMVH3Iy2nW+gbWZKTlNpLO400JV
0n2rPYoi+ad0qKqHK7BnunS5egb6wQeKe3UkPxMCgYAiwfanXc/LHl9gwi6fjWgD
q3VkTQwI7V2eX24ZPMxqOJ+jFtKX9Z0wvnY9aheQQTDi43z72gLKOOrc1Nfisa2O
2ugVhKMZ++CD2nEnxtYdsTNcZO0iCRQuPlA5pfVsrTNNiPqgM45wtloydcXA5eZA
6obTrwVHs4JBfuc6QWowCA==
-----END PRIVATE KEY-----`

	publicKeyStr = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt7xm6wRqeiEKS/EbTRbA
pKfoIZHtTAZv+LJ/ioyxKA4q2/blG0sXJ8n/BYojeiERpvuEJYb15zMll5avrUBK
4/DTZBdsasLEctXM8BHuSw7papdmrsGVkSvoYZW66ElVhD2EIiExBmQj6j+P5HEz
8tdISTKUqFoJDvp1Id46FXM2gI6aj4hBVCoVc8JKPgLX1Hu+TwvH4zUeoBnoG3MC
PGXytND/jFSZRdu4oRgJU6vrwjcZmqZb6LkMfvANJfHBTaEI2SwPhtfMgs3XZ05J
Tp7C7vvsWm0eM99mP2Ict6Q5wA2VyKSUy2VmR/OEp/TFrc4yeeeiJBV8kydaOSVa
WQIDAQAB
-----END PUBLIC KEY-----`
)

func parsePrivateKey(pemPrivateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	if block == nil {
		log.Fatal("failed to decode PEM block containing the private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey.(*rsa.PrivateKey), nil
}

func parsePublicKey(pemPublicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to parse PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

func signMessage(privateKey *rsa.PrivateKey, message []byte) (string, error) {
	hashed := Hash(message)

	// signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA3_224, hashed)
	signature, err := SignPKCS1v15(privateKey, hashA, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func verifySignature(publicKey *rsa.PublicKey, message []byte, encodedSignature string) error {
	hashed := Hash(message)

	fmt.Println("Hash:", hex.EncodeToString(hashed))

	// fmt.Println(hashed)

	// 解码 Base64 签名
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}

	return VerifyPKCS1v15(publicKey, hashA, hashed, signature)
}

var hashA = crypto.SHA3_224

// var hashA = crypto.SHA3_256
// var hashA = crypto.SHA3_384
// var hashA = crypto.SHA3_512

func Hash(message []byte) []byte {
	// hash := sha3.New256()
	// hash := sha3.New384()
	// hash := sha3.New512()
	hash := sha3.New224()
	// hash := sha256.New()
	hash.Write(message)
	return hash.Sum(nil)
}

func TestSignAndVerify(t *testing.T) {
	// Parse the private key
	privateKey, err := parsePrivateKey(privateKeyStr)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	content := `hello world`
	fmt.Println("message is:", content)
	signature, err := signMessage(privateKey, []byte(content))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Signature:", base64.StdEncoding.EncodeToString([]byte(signature)))

	// Parse the public key
	rsaPublicKey, err := parsePublicKey(publicKeyStr)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
		return
	}
	err = verifySignature(rsaPublicKey, []byte(content), signature)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Signature verified successfully")
}
