//
//  Parameters.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

struct DilithiumParameters {
    
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
    
    // Figures from [DILITHIUM] section 4

    // Dilithium 2 parameters
    static let DSA44 = DilithiumParameters(tau: 39, entr: 192, lambda: 128, gamma1: 1 << 17, gamma2:  95232, k: 4, l: 4, eta: 2, beta:  78, omega: 80)
     
    // Dilithium 3 parameters
    static let DSA65 = DilithiumParameters(tau: 49, entr: 225, lambda: 192, gamma1: 1 << 19, gamma2: 261888, k: 6, l: 5, eta: 4, beta: 196, omega: 55)
     
    // Dilithium 5 parameters
    static let DSA87 = DilithiumParameters(tau: 60, entr: 257, lambda: 256, gamma1: 1 << 19, gamma2: 261888, k: 8, l: 7, eta: 2, beta: 120, omega: 75)
     
}
