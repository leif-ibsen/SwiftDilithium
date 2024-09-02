# ``SwiftDilithium``

Module-Lattice-Based Digital Signature Standard

## Overview

SwiftDilithium is a Swift implementation of NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard, August 13, 2024*.

SwiftDilithium functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized, pure or pre-hashed, with or without context
* Verify signatures, pure or pre-hashed, with or without context
* Supports the three Dilithium instances defined in [FIPS 204].

### Example

```swift
import SwiftDilithium

// Create keys

let (sk, pk) = Dilithium.ML_DSA_44.GenerateKeyPair()

// Randomized signature
let randomizedSig = sk.Sign(message: [1, 2, 3], randomize: true)
print("Randomized:", pk.Verify(message: [1, 2, 3], signature: randomizedSig))

// Deterministic signature
let deterministicSig = sk.Sign(message: [1, 2, 3], randomize: false)
print("Deterministic:", pk.Verify(message: [1, 2, 3], signature: deterministicSig))
```
giving:
```swift
Randomized: true
Deterministic: true
```

### Usage

To use SwiftDilithium, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftDilithium", from: "2.0.0"),
]
```

SwiftDilithium itself depends on the Digest package

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.6.0"),
],
```

> Important:
SwiftDilithium requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Structures

- ``SwiftDilithium/Dilithium``
- ``SwiftDilithium/SecretKey``
- ``SwiftDilithium/PublicKey``

### Type Aliases

- ``SwiftDilithium/Byte``
- ``SwiftDilithium/Bytes``

### Enumerations

- ``SwiftDilithium/DilithiumException``
- ``SwiftDilithium/DilithiumPreHash``

### Additional Information

- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:References>
