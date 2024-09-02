# ``SwiftDilithium/PublicKey``

A public key verifies a signature against a message. In the pure version the message itself is verified.
In the pre-hashed version a hash of the message is verified.

> Note:
The `Verify(message:signature:context:)` method throws an exception if the context size is larger than 255.\
The `VerifyPrehash(message:signature:ph:context:)` method returns `false` if the context size is larger than 255.\
This difference in behaviour seems strange, but is how the specification must be understood.

## Topics

### Properties

- ``keyBytes``

### Constructor

- ``init(keyBytes:)``

### Verify

- ``Verify(message:signature:)``
- ``Verify(message:signature:context:)``
- ``VerifyPrehash(message:signature:ph:)``
- ``VerifyPrehash(message:signature:ph:context:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
