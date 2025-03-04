//
//  PublicKey.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

import ASN1
import Digest

public struct PublicKey: CustomStringConvertible, Equatable {
   
    let dilithium: Dilithium
    let signatureSize: Int
    let aHat: Matrix

    // MARK: Properties

    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return ASN1Sequence().add(ASN1Sequence().add(self.dilithium.oid)).add(try ASN1BitString(self.keyBytes, 0)) } catch { return ASN1.NULL } } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PUBLIC KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }


    // MARK: Constructors

    init(_ keyBytes: Bytes, _ dilithium: Dilithium) {
        self.keyBytes = keyBytes
        self.signatureSize = dilithium.sigSize
        self.dilithium = dilithium
        let rho = Bytes(keyBytes[0 ..< 32])
        self.aHat = self.dilithium.ExpandA(rho)
    }

    /// Creates a public key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(keyBytes: Bytes) throws {
        for kind in Kind.allCases {
            if keyBytes.count == Parameters.paramsFromKind(kind).pkSize {
                self.init(keyBytes, Dilithium(kind))
                return
            }
        }
        throw Exception.publicKeySize(value: keyBytes.count)
    }

    /// Creates a public key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The public key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PUBLIC KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 2 {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(0) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let bits = seq.get(1) as? ASN1BitString else {
            throw Exception.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Exception.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Exception.asn1Structure
        }
        guard bits.unused == 0 else {
            throw Exception.asn1Structure
        }
        if oid == Parameters.DSA44.oid && bits.bits.count == Parameters.DSA44.pkSize {
            try self.init(keyBytes: bits.bits)
        } else if oid == Parameters.DSA65.oid && bits.bits.count == Parameters.DSA65.pkSize {
            try self.init(keyBytes: bits.bits)
        } else if oid == Parameters.DSA87.oid && bits.bits.count == Parameters.DSA87.pkSize {
            try self.init(keyBytes: bits.bits)
        } else {
            throw Exception.asn1Structure
        }
    }


    // MARK: Instance Methods

    /// Verifies a signature - pure version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes) -> Bool {
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.Verify(self.keyBytes, message, signature, [], self.aHat)
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
            throw Exception.contextSize(value: context.count)
        }
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.Verify(self.keyBytes, message, signature, context, self.aHat)
    }

    /// Verifies a signature - pre-hashed version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes, ph: PreHash) -> Bool {
        guard signature.count == self.signatureSize else {
            return false
        }
        return self.dilithium.hashVerify(self.keyBytes, message, signature, [], ph, self.aHat)
    }

    /// Verifies a signature - pre-hashed version with context
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    ///   - context: The context string
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes, ph: PreHash, context: Bytes) -> Bool {
        guard signature.count == self.signatureSize && context.count < 256 else {
            return false
        }
        return self.dilithium.hashVerify(self.keyBytes, message, signature, context, ph, self.aHat)
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
