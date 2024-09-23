# Key Management

##

SwiftDilithium keys can be stored in their PEM encoded ASN1 representation and recreated later.

### Example

```swift
import SwiftDilithium

let (secretKey, publicKey) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)

let secretKeyPem = secretKey.pem
let publicKeyPem = publicKey.pem

print(secretKeyPem)
print()
print(publicKeyPem)
print()

let newSecretKey = try SecretKey(pem: secretKeyPem)
let newPublicKey = try PublicKey(pem: publicKeyPem)

assert(newSecretKey == secretKey)
assert(newPublicKey == publicKey)

print(newSecretKey)
print(newPublicKey)
```

Giving (for example):

```
-----BEGIN PRIVATE KEY-----
MIIKGAIBADALBglghkgBZQMEAxEEggoEBIIKAD+yY4xgm42d5B1swew9a6sfdPca2xcFdF/ODw7B
CFL3QTLrbX1sgOIRXqqegwagtBPX2DcjEBPhHykjkOkqhkHjPLKNpRf8MRQfOx6YJ5V74F/w6ITP

... 41 more lines

WlomFTDtImmfHo97bXYZ3RxN+daB6tx8BcNzifgrbOGcS8t+zfwVo7DQjW0DulMNaWjMZl47dKs5
vLVFg6x4yrYPrflPnfefS0hZvrErOT2eGEWM9GeI37bjcRnx/4mL1sQk0s4ovFuWcdE21tsbRyGR
y9NOmXPyutOYVRtKEYwjbuNbJz7qzgs=
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhAD+yY4xgm42d5B1swew9a6sfdPca2xcFdF/ODw7BCFL3j/Py
nMODat+qOuS5O/RfT1FxQgihnPRUTWHwANRllFnUQCBOQfjQLQbw+M6Ix1jGRjDyYZbVqwNM18oU

... 19 more lines

AVIF4eIPLhdfha//h+aVDx70GAyQsLwXJUX9ztu9ao+LdN74ELUsg8iV1nNVhiDMPN2/lnfF9DNn
XD+7VEkNevZYr2FwE8fN8UKIoo2uSQM+O7icIlEdZAbkhnkWyKrpzk4DFphZGqBEvDxFQZtuX4X5
KYbyeRgOxwD9s0j75fw1ClMhVo249mM=
-----END PUBLIC KEY-----

Sequence (3):
  Integer: 0
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.3.17
  Octet String (2564): 04 82 0a 00 3f b2 63 8c 60 9b 8d 9d e4 1d 6c c1 ec 3d 6b
     ab 1f 74 f7 1a db 17 05 74 5f ce 0f 0e c1 08 52 f7 41 32 eb 6d 7d 6c 80 e2
  
     ... 2462 more bytes
     
     3d 9e 18 45 8c f4 67 88 df b6 e3 71 19 f1 ff 89 8b d6 c4 24 d2 ce 28 bc 5b
     96 71 d1 36 d6 db 1b 47 21 91 cb d3 4e 99 73 f2 ba d3 98 55 1b 4a 11 8c 23
     6e e3 5b 27 3e ea ce 0b

Sequence (2):
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.3.17
  Bit String (10496): 00111111 10110010 01100011 10001100 01100000 10011011 10001101
    10011101 11100100 00011101 01101100 11000001 11101100 00111101 01101011 10101011

    ... 10160 more bits  
  
    01011111 10000101 11111001 00101001 10000110 11110010 01111001 00011000 00001110
    11000111 00000000 11111101 10110011 01001000 11111011 11100101 11111100 00110101
    00001010 01010011 00100001 01010110 10001101 10111000 11110110 01100011
```