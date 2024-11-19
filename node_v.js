const crypto = require('crypto');

// 假设你有公钥和私钥
const privateKey = `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`;

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt7xm6wRqeiEKS/EbTRbA
pKfoIZHtTAZv+LJ/ioyxKA4q2/blG0sXJ8n/BYojeiERpvuEJYb15zMll5avrUBK
4/DTZBdsasLEctXM8BHuSw7papdmrsGVkSvoYZW66ElVhD2EIiExBmQj6j+P5HEz
8tdISTKUqFoJDvp1Id46FXM2gI6aj4hBVCoVc8JKPgLX1Hu+TwvH4zUeoBnoG3MC
PGXytND/jFSZRdu4oRgJU6vrwjcZmqZb6LkMfvANJfHBTaEI2SwPhtfMgs3XZ05J
Tp7C7vvsWm0eM99mP2Ict6Q5wA2VyKSUy2VmR/OEp/TFrc4yeeeiJBV8kydaOSVa
WQIDAQAB
-----END PUBLIC KEY-----`;

const timestamp = 1731661401820;
const message = 'hello world';
console.log("message is:", message);

const algorithm = 'RSA-SHA3-224'

hash = crypto.createHash("SHA3-224").update(message).digest("hex");
console.log(`Hash: ${hash}`);

// 使用 SHA-3-256 和 RSA 签名（默认 PKCS1v15 填充）
const sign = crypto.createSign(algorithm);
sign.update(message);
sign.end();
var signature = sign.sign(privateKey);
console.log(`Signature: ${signature.toString('base64')}`);

// 使用公钥验证签名
const verify = crypto.createVerify(algorithm);
verify.update(message);
verify.end();
const isValid = verify.verify(publicKey, signature);
console.log(`Signature is valid: ${isValid}`);

