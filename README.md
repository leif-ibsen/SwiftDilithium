## SwiftDilithium

SwiftDilithium is a Swift implementation of NIST FIPS 204 (Draft): *Module-Lattice-Based Digital Signature Standard, August 2023*.

SwiftDilithium functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Supports the three Dilithium instances defined in the proposed standard

SwiftDilithium requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftDilithium/documentation/swiftdilithium

The documentation is also available in the *SwiftDilithium.doccarchive* file.
