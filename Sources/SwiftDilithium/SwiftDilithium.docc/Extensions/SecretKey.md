# ``SwiftDilithium/SecretKey``

A secret key signs a message. In the pure version the message itself is signed.
In the pre-hashed version a hash of the message using one of the ``DilithiumPreHash`` functions is signed.

## Topics

### Properties

- ``keyBytes``

### Constructor

- ``init(keyBytes:)``

### Sign

- ``Sign(message:randomize:)``
- ``Sign(message:context:randomize:)``
- ``SignPrehash(message:ph:randomize:)``
- ``SignPrehash(message:ph:context:randomize:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
