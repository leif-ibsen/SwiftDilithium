//
//  Exception.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 08/03/2024.
//

/// The Dilithium exceptions
public enum DilithiumException: Error {
    
    /// Wrong public key size
    case publicKeySize(value: Int)

    /// Wrong secret key size
    case secretKeySize(value: Int)
    
}
