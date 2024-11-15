package handler

import (
	"crypto/rand"
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
	publicKeyStr = `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB1KCqLRzqeRMpOh//gll08
/Xmoh1r8suUszvC3H1dG2mz/cEos3jG0AI+67ba5D1bSpIJCfOaHCPNAFqZiKaSR
X9QiWlnTqgyt45MUS5dZtRE4DA/pmzHa2NEW0yXeheycSbT4Yurw804ofB4wTVwk
PEF0+9bdBB544ZGxZegiGC9NQTrfqLiCO8fCHWsPbKYix97k0gfFl0NHhX+UB1pL
g5MPVk255mr7+63ymgc42ryhtx0f+aZALISdl/tfH7f35h4dE7kPJlGv6e7bgKVA
HIFB9sfcWUs70/Cpa5rN0u4P14NHRZWHY/Lhv3uJEm6owr1WKA3nAQTHKdshcFar
AgMBAAE=
-----END PUBLIC KEY-----`
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

	publicKeyStr1 = `-----BEGIN PUBLIC KEY-----

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
	// 计算 SHA3-256 哈希值
	hash := sha3.New256()
	// hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	// 使用 RSA PKCS1v15 签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hashed)
	if err != nil {
		return "", err
	}

	// 返回 Base64 编码的签名
	return base64.StdEncoding.EncodeToString(signature), nil
}

func verifySignature(publicKey *rsa.PublicKey, message []byte, encodedSignature string) error {
	// 计算 SHA3-256 哈希值
	hash := sha3.New256()
	// hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	fmt.Println(hex.EncodeToString(hashed))

	// fmt.Println(hashed)

	// 解码 Base64 签名
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}

	// 使用 RSA PKCS1v15 验证签名
	// return rsa.VerifyPKCS1v15(publicKey, 0, hashed, signature)
	return VerifyPKCS1v15(publicKey, 0, hashed, signature)
}

func TestSignAndVerify(t *testing.T) {
	// Parse the private key
	privateKey, err := parsePrivateKey(privateKeyStr)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	timestamp := 1731661401820
	eventMessage := `test message`
	content := fmt.Sprintf(eventMessage, timestamp)
	fmt.Println(content)
	signature, err := signMessage(privateKey, []byte(content))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(signature)

	// Parse the public key
	rsaPublicKey, err := parsePublicKey(publicKeyStr1)
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

// func TestSignatureVerify(t *testing.T) {
// 	timestamp := 1731661401820
// 	eventMessage := `test message %d`
// 	signatureStr := `X0l+otjBzSW6WpzTXmk+qP6no4JvkrxC9I+T3fc6dQNKG1MQYxjhPXE1WZsA9PX58ZTLez9puZh37vsr6b6eVt4MCtbn/XTJEQdBJ6nx0CceQUQDeiZsna1l1q7QCZoWQsnlUiD0H+v1LtUtLpkyF/b5dDi6cKQSy4LfBxUe/kRj/wcYu9FuLuN/eQ++lzWOmF1I9l8XvxWblM2R9DsOq9Frel3BE/DrdubUrpsU/TLRAYkBxYf9BX0fWBwP/kb6rWq13KmreDJzdBcnd5GXz8hOCRtpuAZqg68gJEeCi8QJsRGjTCNaKM/0cC9M6xgc2R0wyfXkpu17beOJXFf23w==`
// 	content := fmt.Sprintf(eventMessage, timestamp)

// 	fmt.Println(content)

// 	// Parse the public key
// 	rsaPublicKey, err := parsePublicKey(publicKeyStr)
// 	if err != nil {
// 		log.Fatalf("Failed to parse public key: %v", err)
// 		return
// 	}

// 	hash := sha3.New256()
// 	hash.Write([]byte(content))
// 	hashed := hash.Sum(nil)

// 	signature, err := base64.StdEncoding.DecodeString(signatureStr)
// 	if err != nil {
// 		log.Fatalf("Failed to parse public key: %v", err)
// 		return
// 	}

// 	// Verify the signature
// 	err = VerifyPKCS1v15(rsaPublicKey, crypto.SHA3_256, []byte(hashed), []byte(signature))
// 	if err != nil {
// 		fmt.Println("Signature verification failed:", err)
// 	} else {
// 		fmt.Println("Signature is valid")
// 	}
// }
