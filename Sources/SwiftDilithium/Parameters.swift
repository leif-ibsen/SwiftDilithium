//
//  Parameters.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

import ASN1

struct Parameters {
    
    let tau: Int
    let entr: Int
    let lambda: Int
    let gamma1: Int
    let gamma2: Int
    let k: Int
    let l: Int
    let eta: Int
    let beta: Int
    let omega: Int
    let sigSize: Int
    let pkSize: Int
    let skSize: Int
    let oid: ASN1ObjectIdentifier
    
    // Figures from [DILITHIUM] section 4

    static let params: [Parameters] = [
        // Dilithium 2 parameters
        Parameters(tau: 39, entr: 192, lambda: 128, gamma1: 1 << 17, gamma2:  95232, k: 4, l: 4, eta: 2, beta:  78, omega: 80,
                   sigSize: 2420, pkSize: 1312, skSize: 2560, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17")!),
        // Dilithium 3 parameters
        Parameters(tau: 49, entr: 225, lambda: 192, gamma1: 1 << 19, gamma2: 261888, k: 6, l: 5, eta: 4, beta: 196, omega: 55,
                   sigSize: 3309, pkSize: 1952, skSize: 4032, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18")!),
        // Dilithium 5 parameters
        Parameters(tau: 60, entr: 257, lambda: 256, gamma1: 1 << 19, gamma2: 261888, k: 8, l: 7, eta: 2, beta: 120, omega: 75,
                   sigSize: 4627, pkSize: 2592, skSize: 4896, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19")!)
        ]
    
    // Dilithium 2 parameters
    static let DSA44 = Parameters(tau: 39, entr: 192, lambda: 128, gamma1: 1 << 17, gamma2:  95232, k: 4, l: 4, eta: 2, beta:  78, omega: 80,
                                  sigSize: 2420, pkSize: 1312, skSize: 2560, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17")!)
     
    // Dilithium 3 parameters
    static let DSA65 = Parameters(tau: 49, entr: 225, lambda: 192, gamma1: 1 << 19, gamma2: 261888, k: 6, l: 5, eta: 4, beta: 196, omega: 55,
                                  sigSize: 3309, pkSize: 1952, skSize: 4032, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18")!)
     
    // Dilithium 5 parameters
    static let DSA87 = Parameters(tau: 60, entr: 257, lambda: 256, gamma1: 1 << 19, gamma2: 261888, k: 8, l: 7, eta: 2, beta: 120, omega: 75,
                                  sigSize: 4627, pkSize: 2592, skSize: 4896, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19")!)
     
    static func paramsFromKind(_ kind: Kind) -> Parameters {
        return params[kind.rawValue]
    }
    
    static func kindFromOID(_ oid: ASN1ObjectIdentifier) -> Kind? {
        for kind in Kind.allCases {
            if paramsFromKind(kind).oid == oid {
                return kind
            }
        }
        return nil
    }

}
