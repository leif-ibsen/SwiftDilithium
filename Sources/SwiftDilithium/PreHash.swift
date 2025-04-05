//
//  File.swift
//  
//
//  Created by Leif Ibsen on 18/09/2024.
//

/// The Dilithium pre-hash functions
public enum PreHash {

    /// SHA2-224 message digest
    case SHA2_224
    
    /// SHA2-256 message digest
    case SHA2_256
    
    /// SHA2-384 message digest
    case SHA2_384
    
    /// SHA2-512 message digest
    case SHA2_512
    
    /// SHA2-512/224 message digest
    case SHA2_512_224
    
    /// SHA2-512/256 message digest
    case SHA2_512_256

    /// SHA3-224 message digest
    case SHA3_224
    
    /// SHA3-256 message digest
    case SHA3_256
    
    /// SHA3-384 message digest
    case SHA3_384
    
    /// SHA3-512 message digest
    case SHA3_512

    /// Same as SHA2_256
    case SHA256

    /// Same as SHA2_512
    case SHA512

    /// SHAKE128 extendable output function
    case SHAKE128

    /// SHAKE256 extendable output function
    case SHAKE256

}
