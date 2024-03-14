//
//  MakeHintTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class MakeHintTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        for _ in 0 ..< 20 {
            let z = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
            let r = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
            let h = d.MakeHint(z, r)
            let r1 = d.UseHint(h, r)
            XCTAssertTrue(0 <= r1)
            XCTAssertTrue(r1 <= (Dilithium.Q - 1) / (d.gamma2 * 2))
        }
    }

    func test() throws {
        doTest(Dilithium.D2)
        doTest(Dilithium.D3)
        doTest(Dilithium.D5)
    }

}
