# ``SwiftDilithium``

Module-Lattice-Based Digital Signature Standard

## Overview

SwiftDilithium is a Swift implementation of NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard, August 13, 2024*.

SwiftDilithium functionality:

* Support for the three Dilithium kinds defined in [FIPS 204]
* Create public and secret keys
* Sign messages - deterministically or randomized, pure or pre-hashed, with or without context
* Verify signatures, pure or pre-hashed, with or without context
* Store keys in their PEM encoded ASN1 representation
* Restore keys from their PEM encoded ASN1 representation

### Usage

To use SwiftDilithium, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftDilithium", from: "3.1.0"),
]
```

SwiftDilithium itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint) and [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.6.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.19.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.8.0"),
],
```

SwiftDilithium does not do big integer arithmetic, but the ASN1 package depends on the BigInt package.

> Important:
SwiftDilithium requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Structures

- ``SwiftDilithium/Dilithium``
- ``SwiftDilithium/SecretKey``
- ``SwiftDilithium/PublicKey``

### Enumerations

- ``SwiftDilithium/Kind``
- ``SwiftDilithium/PreHash``
- ``SwiftDilithium/Exception``

### Type Aliases

- ``SwiftDilithium/Byte``
- ``SwiftDilithium/Bytes``

### Additional Information

- <doc:SignVerify>
- <doc:KeyManagement>
- <doc:OIDs>
- <doc:Performance>
- <doc:References>
