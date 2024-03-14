//
//  Power2RoundTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class Power2RoundTest: XCTestCase {

    func test() throws {
        for _ in 0 ..< 100 {
            let r = Int.random(in: -Dilithium.Q + 1 ..< Dilithium.Q)
            let (r1, r0) = Dilithium.Power2Round(r)
            XCTAssertTrue(Dilithium.modQ(r - r1 << Dilithium.D - r0) == 0)
        }
    }

}
