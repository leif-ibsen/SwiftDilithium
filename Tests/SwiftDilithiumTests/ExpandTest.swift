//
//  ExpandTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class ExpandTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        var rho = Bytes(repeating: 0, count: 64)
        Dilithium.randomBytes(&rho)
        let v = d.ExpandMask(rho, 100)
        for i in 0 ..< v.n {
            for j in 0 ..< 256 {
                XCTAssertTrue(v.polynomial[i].coef[j] <= d.gamma1)
                XCTAssertTrue(v.polynomial[i].coef[j] >= -d.gamma1 + 1)
            }
        }
        let (v1, v2) = d.ExpandS(rho)
        for i in 0 ..< v1.n {
            for j in 0 ..< 256 {
                XCTAssertTrue(v1.polynomial[i].coef[j] <= d.eta)
                XCTAssertTrue(v1.polynomial[i].coef[j] >= -d.eta)
                XCTAssertTrue(v2.polynomial[i].coef[j] <= d.eta)
                XCTAssertTrue(v2.polynomial[i].coef[j] >= -d.eta)
            }
        }
    }

    func test() throws {
        doTest(Dilithium.D2)
        doTest(Dilithium.D3)
        doTest(Dilithium.D5)
    }

}
