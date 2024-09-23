//
//  File.swift
//  
//
//  Created by Leif Ibsen on 18/09/2024.
//

/// The Dilithium exceptions
public enum Exception: Error {

    /// Wrong ASN1 structure
    case asn1Structure
    
    /// Wrong context size
    case contextSize(value: Int)
    
    /// Wrong PEM structure
    case pemStructure
    
    /// Wrong public key size
    case publicKeySize(value: Int)
    
    /// Wrong secret key size
    case secretKeySize(value: Int)
    
}
