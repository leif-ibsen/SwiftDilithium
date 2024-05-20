# ``SwiftDilithium``

Module-Lattice-Based Digital Signature Standard

## Overview

SwiftDilithium is a Swift implementation of NIST FIPS 204 (Draft): *Module-Lattice-Based Digital Signature Standard, August 2023*.

SwiftDilithium functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Supports the three Dilithium instances defined in [FIPS 204].

### Example

```swift
import SwiftDilithium

// Create keys

let (sk, pk) = Dilithium.D2.GenerateKeyPair()

// Deterministic signature
let deterministicSig = sk.Sign(message: [1, 2, 3], deterministic: true)
print("Deterministic:", pk.Verify(signature: deterministicSig, message: [1, 2, 3]))

// Randomized signature
let randomizedSig = sk.Sign(message: [1, 2, 3], deterministic: false)
print("Randomized:", pk.Verify(signature: randomizedSig, message: [1, 2, 3]))
```
giving:
```swift
Deterministic: true

Randomized: true
```

### Usage

To use SwiftDilithium, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftDilithium", from: "1.1.0"),
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

### Additional Information

- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:References>
