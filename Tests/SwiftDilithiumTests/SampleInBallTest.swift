//
//  SampleInBallTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class SampleInBallTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        let rho = Dilithium.randomBytes(d.lambda >> 2)
        let v = d.SampleInBall(rho)
        var x0 = 0
        var x1 = 0
        var x_1 = 0
        for i in 0 ..< 256 {
            if v.coef[i] == 0 {
                x0 += 1
            } else if v.coef[i] == 1 {
                x1 += 1
            } else if v.coef[i] == -1 {
                x_1 += 1
            }
        }
        XCTAssertEqual(x0 + x1 + x_1, 256)
    }

    func test() throws {
        doTest(Dilithium.ML_DSA_44)
        doTest(Dilithium.ML_DSA_65)
        doTest(Dilithium.ML_DSA_87)
    }

}
