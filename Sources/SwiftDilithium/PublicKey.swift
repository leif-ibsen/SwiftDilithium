//
//  PublicKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

/// The Dilithium public key
public struct PublicKey {
   
    let signatureSize: Int
    let dilithium: Dilithium

    /// The key bytes
    public let keyBytes: Bytes

    /// Creates a public key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(keyBytes: Bytes) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Dilithium.DSA44pkSize {
            self.dilithium = Dilithium.ML_DSA_44
            self.signatureSize = 2420
        } else if keyBytes.count == Dilithium.DSA65pkSize {
            self.dilithium = Dilithium.ML_DSA_65
            self.signatureSize = 3309
        } else if keyBytes.count == Dilithium.DSA87pkSize {
            self.dilithium = Dilithium.ML_DSA_87
            self.signatureSize = 4627
        } else {
            throw DilithiumException.publicKeySize(value: keyBytes.count)
        }
    }

    /// Verifies a signature - pure version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes) -> Bool {
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.Verify(self.keyBytes, message, signature, [])
    }

    /// Verifies a signature - pure version with context
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - context: The context string
    /// - Returns: `true` if the signature is verified, else `false`
    /// - Throws: An exception if the context size is larger than 255
    public func Verify(message: Bytes, signature: Bytes, context: Bytes) throws -> Bool {        
        guard context.count < 256 else {
            throw DilithiumException.contextSize(value: context.count)
        }
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.Verify(self.keyBytes, message, signature, context)
    }

    /// Verifies a signature - pre-hashed version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    /// - Returns: `true` if the signature is verified, else `false`
    public func VerifyPrehash(message: Bytes, signature: Bytes, ph: DilithiumPreHash) -> Bool {
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.hashVerify(self.keyBytes, message, signature, [], ph)
    }

    /// Verifies a signature - pre-hashed version with context
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    ///   - context: The context string
    /// - Returns: `true` if the signature is verified, else `false`
    public func VerifyPrehash(message: Bytes, signature: Bytes, ph: DilithiumPreHash, context: Bytes) -> Bool {
        guard signature.count == self.signatureSize && context.count < 256 else {
            return false
        }
        return self.dilithium.hashVerify(self.keyBytes, message, signature, context, ph)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}
