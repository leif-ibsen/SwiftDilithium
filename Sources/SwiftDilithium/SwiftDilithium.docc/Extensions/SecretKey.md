# ``SwiftDilithium/SecretKey``

The SecretKey structure

## Overview

A secret key signs a message. In the pure version the message itself is signed.
In the pre-hashed version a hash of the message using one of the ``PreHash`` functions is signed.

## Topics

### Properties

- ``keyBytes``
- ``asn1``
- ``pem``
- ``description``

### Constructors

- ``init(keyBytes:)``
- ``init(pem:)``

### Sign

- ``Sign(message:randomize:)``
- ``Sign(message:context:randomize:)``
- ``Sign(message:ph:randomize:)``
- ``Sign(message:ph:context:randomize:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
