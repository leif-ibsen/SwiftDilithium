//
//  PrivateKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 08/03/2024.
//

import ASN1
import Digest

public struct SecretKey: CustomStringConvertible, Equatable {
    
    let dilithium: Dilithium


    // MARK: Properties

    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1.ZERO).add(ASN1Sequence().add(self.dilithium.oid)).add(ASN1OctetString(ASN1OctetString(self.keyBytes).encode())) } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }


    // MARK: Constructors

    init(_ keyBytes: Bytes, _ dilithium: Dilithium) {
        self.keyBytes = keyBytes
        self.dilithium = dilithium
    }

    /// Creates a secret key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(keyBytes: Bytes) throws {
        for kind in Kind.allCases {
            if keyBytes.count == Parameters.paramsFromKind(kind).skSize {
                self.init(keyBytes, Dilithium(kind))
                return
            }
        }
        throw Exception.secretKeySize(value: keyBytes.count)
    }

    /// Creates a secret key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The secret key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PRIVATE KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw Exception.asn1Structure
        }
        guard let int = seq.get(0) as? ASN1Integer else {
            throw Exception.asn1Structure
        }
        if int != ASN1.ZERO {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let octets = seq.get(2) as? ASN1OctetString else {
            throw Exception.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Exception.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Exception.asn1Structure
        }
        if oid != Parameters.DSA44.oid && oid != Parameters.DSA65.oid && oid != Parameters.DSA87.oid {
            throw Exception.asn1Structure
        }
        guard let seq2 = try ASN1.build(octets.value) as? ASN1OctetString else {
            throw Exception.asn1Structure
        }
        try self.init(keyBytes: seq2.value)
    }


    // MARK: Instance Methods

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
            throw Exception.contextSize(value: context.count)
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
    public func Sign(message: Bytes, ph: PreHash, randomize: Bool = true) -> Bytes {
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
    public func Sign(message: Bytes, ph: PreHash, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw Exception.contextSize(value: context.count)
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
