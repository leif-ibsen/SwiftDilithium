//
//  PrivateKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 08/03/2024.
//

/// The Dilithium secret key
public struct SecretKey {
    
    let dilithium: Dilithium
    
    /// The key bytes
    public let keyBytes: Bytes

    /// Creates a secret key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(keyBytes: Bytes) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Dilithium.DSA44skSize {
            self.dilithium = Dilithium.ML_DSA_44
        } else if keyBytes.count == Dilithium.DSA65skSize {
            self.dilithium = Dilithium.ML_DSA_65
        } else if keyBytes.count == Dilithium.DSA87skSize {
            self.dilithium = Dilithium.ML_DSA_87
        } else {
            throw DilithiumException.secretKeySize(value: keyBytes.count)
        }
    }
    
    /// Signs a message - pure version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func Sign(message: Bytes, randomize: Bool = true) -> Bytes {
        return self.dilithium.Sign(self.keyBytes, message, [], randomize)
    }
    
    /// Signs a message - pure version with context
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - context: The context string
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    /// - Throws: An exception if the context size is larger than 255
    public func Sign(message: Bytes, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw DilithiumException.contextSize(value: context.count)
        }
        return self.dilithium.Sign(self.keyBytes, message, context, randomize)
    }
    
    /// Signs a message - pre-hashed version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - ph: The pre-hash function
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func SignPrehash(message: Bytes, ph: DilithiumPreHash, randomize: Bool = true) -> Bytes {
        return self.dilithium.hashSign(self.keyBytes, message, [], ph, randomize)
    }
    
    /// Signs a message - pre-hashed version with context
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - ph: The pre-hash function
    ///   - context: The context string
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    /// - Throws: An exception if the context size is larger than 255
    public func SignPrehash(message: Bytes, ph: DilithiumPreHash, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw DilithiumException.contextSize(value: context.count)
        }
        return self.dilithium.hashSign(self.keyBytes, message, context, ph, randomize)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}
