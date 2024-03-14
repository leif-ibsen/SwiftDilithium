//
//  PrivateKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 08/03/2024.
//

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
        try self.init(keyBytes, true)
    }
    
    init(_ keyBytes: Bytes, _ check: Bool) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Dilithium.D2skSize {
            self.dilithium = Dilithium.D2
        } else if keyBytes.count == Dilithium.D3skSize {
            self.dilithium = Dilithium.D3
        } else if keyBytes.count == Dilithium.D5skSize {
            self.dilithium = Dilithium.D5
        } else {
            throw DilithiumException.secretKeySize(value: keyBytes.count)
        }
    }

    /// Signs a message
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - deterministic: If `true`, generate a deterministic signature, else generate a randomized signature, default is `false`
    /// - Returns: The signature
    public func Sign(message: Bytes, deterministic: Bool = false) -> Bytes {
        return self.dilithium.Sign(self.keyBytes, message, deterministic)
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
