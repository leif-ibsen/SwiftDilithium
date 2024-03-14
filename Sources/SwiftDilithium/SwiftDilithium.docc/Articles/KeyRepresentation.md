# Key Representation

SwiftDilithium keys can be stored as raw bytes and later recreated from the stored bytes

## 

### Example

```swift
import SwiftDilithium

let (sk, pk) = Dilithium.D2.GenerateKeyPair()

let skKeyBytes = sk.keyBytes
let pkKeyBytes = pk.keyBytes

let newSecretKey = try SecretKey(keyBytes: skKeyBytes)
let newPublicKey = try PublicKey(keyBytes: pkKeyBytes)

// newSecretKey is now equal to sk and newPublicKey is equal to pk

assert(newSecretKey == sk)
assert(newPublicKey == pk)
```
