//
//  NTTTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class NTTTest: XCTestCase {
    
    // Polynomial multiplication in Z[X]/(X^256 + 1)
    // KNUTH - section 4.6.1
    func mulP(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var u = [Int](repeating: 0, count: 512)
        var q = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            for j in 0 ..< 256 {
                u[i + j] += p1.coef[i] * p2.coef[j]
            }
        }
        for i in 0 ..< 512 {
            u[i] = u[i] % Dilithium.Q
        }
        for k in (0 ..< 256).reversed() {
            q[k] = u[256 + k]
            u[k + 256] -= q[k]
            u[k] -= q[k]
        }
        // u = remainder dividing u by X^256 + 1
        return Polynomial([Int](u[0 ..< 256]))
    }

    func test1() throws {
        for _ in 0 ..< 10 {
            var c1 = [Int](repeating: 0, count: 256)
            var c2 = [Int](repeating: 0, count: 256)
            for i in 0 ..< 256 {
                c1[i] = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
                c2[i] = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
            }
            let p1 = Polynomial(c1)
            let p2 = Polynomial(c2)
            
            // Schoolbook multiplication in Z[X]/(X^256 + 1)
            let px = mulP(p1, p2)
            
            // NTT multiplication
            let py = (p1.NTT() * p2.NTT()).INTT()
            
            // Results must be equal mod Q
            for i in 0 ..< 256 {
                XCTAssertTrue((px.coef[i] - py.coef[i]) % Dilithium.Q == 0)
            }
        }
    }

    func test2() throws {
        for _ in 0 ..< 1 {
            var p = Polynomial()
            for i in 0 ..< 256 {
                p.coef[i] = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
            }
            let p1 = p.NTT().INTT()
            for i in 0 ..< 256 {
                XCTAssertTrue((p1.coef[i] - p.coef[i]) % Dilithium.Q == 0)
            }
        }
    }

}
