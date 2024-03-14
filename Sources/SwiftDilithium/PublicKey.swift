//
//  PublicKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

public struct PublicKey {
   
    let dilithium: Dilithium

    /// The key bytes
    public let keyBytes: Bytes

    /// Creates a public key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(keyBytes: Bytes) throws {
        try self.init(keyBytes, true)
    }
    
    init(_ keyBytes: Bytes, _ check: Bool) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Dilithium.D2pkSize {
            self.dilithium = Dilithium.D2
        } else if keyBytes.count == Dilithium.D3pkSize {
            self.dilithium = Dilithium.D3
        } else if keyBytes.count == Dilithium.D5pkSize {
            self.dilithium = Dilithium.D5
        } else {
            throw DilithiumException.publicKeySize(value: keyBytes.count)
        }
    }

    /// Verifies a signature
    /// 
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - message: The message to verify against
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(signature: Bytes, message: Bytes) -> Bool {
        return self.dilithium.Verify(self.keyBytes, message, signature)
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
