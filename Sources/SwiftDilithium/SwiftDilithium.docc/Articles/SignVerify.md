# Sign and Verify

##

Messages are signed by secret keys and signatures are verified by public keys.
Signatures can be deterministic or randomized and optionally a hash of the message can be signed
instead of the message itself.

### Example

```swift
import SwiftDilithium

// Create keys

let (secretKey, publicKey) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)

// Deterministic signature
let deterministicSig = secretKey.Sign(message: [1, 2, 3], randomize: false)
print("Deterministic:", publicKey.Verify(message: [1, 2, 3], signature: deterministicSig))

// Randomized signature
let randomizedSig = secretKey.Sign(message: [1, 2, 3], randomize: true)
print("Randomized:", publicKey.Verify(message: [1, 2, 3], signature: randomizedSig))

// Prehashed signature
let prehashedSig = secretKey.Sign(message: [1, 2, 3], ph: .SHAKE128)
print("Prehashed:", publicKey.Verify(message: [1, 2, 3], signature: prehashedSig, ph: .SHAKE128))
```

giving:

```
Deterministic: true
Randomized: true
Prehashed: true
```