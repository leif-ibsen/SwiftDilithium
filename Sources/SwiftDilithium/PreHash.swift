//
//  File.swift
//  
//
//  Created by Leif Ibsen on 24/08/2024.
//

/// The Dilithium pre-hash functions
public enum DilithiumPreHash {

    /// SHA2-256 message digest
    case SHA256

    /// SHA2-512 message digest
    case SHA512

    /// SHAKE128 extendable output function
    case SHAKE128

    /// SHAKE256 extendable output function
    case SHAKE256

}
