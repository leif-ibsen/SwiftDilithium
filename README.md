## SwiftDilithium

SwiftDilithium is a Swift implementation of NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard, August 13, 2024*.

SwiftDilithium functionality:

* Support for the three Dilithium instances defined in the standard
* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Store keys in their PEM encoded ASN1 representation
* Restore keys from their PEM encoded ASN1 representation

SwiftDilithium requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftDilithium/documentation/swiftdilithium

The documentation is also available in the *SwiftDilithium.doccarchive* file.

The KAT test vectors come from GitHub ACVP-server release 1.1.0.35.
