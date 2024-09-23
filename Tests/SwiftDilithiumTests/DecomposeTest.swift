//
//  DecomposeTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class DecomposeTest: XCTestCase {

    func doTest(_ kind: Kind) {
        let d = Dilithium(kind)
        for _ in 0 ..< 100 {
            let r = Int.random(in: 0 ..< Dilithium.Q)
            let (r1, r0) = d.Decompose(r)
            XCTAssertTrue(Dilithium.modQ(r - (r1 * 2 * d.gamma2 + r0)) == 0)
        }
    }

    func test() throws {
        doTest(.ML_DSA_44)
        doTest(.ML_DSA_65)
        doTest(.ML_DSA_87)
    }

}
