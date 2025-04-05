//
//  File.swift
//  
//
//  Created by Leif Ibsen on 10/03/2024.
//

import Foundation
import XCTest
@testable import SwiftDilithium

struct Util {

    static func preHash(_ hashAlg: String) -> PreHash? {
        if hashAlg == "none" {
            return nil
        }
        if hashAlg == "SHA2-224" {
            return .SHA2_224
        }
        if hashAlg == "SHA2-256" {
            return .SHA2_256
        }
        if hashAlg == "SHA2-384" {
            return .SHA2_384
        }
        if hashAlg == "SHA2-512" {
            return .SHA2_512
        }
        if hashAlg == "SHA2-512/224" {
            return .SHA2_512_224
        }
        if hashAlg == "SHA2-512/256" {
            return .SHA2_512_256
        }
        if hashAlg == "SHA3-224" {
            return .SHA3_224
        }
        if hashAlg == "SHA3-256" {
            return .SHA3_256
        }
        if hashAlg == "SHA3-384" {
            return .SHA3_384
        }
        if hashAlg == "SHA3-512" {
            return .SHA3_512
        }
        if hashAlg == "SHAKE-128" {
            return .SHAKE128
        }
        if hashAlg == "SHAKE-256" {
            return .SHAKE256
        }
        fatalError("Wrong hash algorithm: \(hashAlg)")
    }

    static func dilithiumKind(_ kind: String) -> Kind {
        switch kind {
        case "ML-DSA-44":
            return .ML_DSA_44
        case "ML-DSA-65":
            return .ML_DSA_65
        case "ML-DSA-87":
            return .ML_DSA_87
        default:
            fatalError("Wrong Dilithium kind: \(kind)")
        }
    }

}
