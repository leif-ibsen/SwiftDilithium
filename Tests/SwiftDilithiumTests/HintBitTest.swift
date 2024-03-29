//
//  HintBitTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class HintBitTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        var h = Vector(d.k)
        for i in 0 ..< d.omega {
            h.polynomial[i & 3].coef[(i >> 2) * 3] = 1
        }
        let x = d.HintBitPack(h)
        XCTAssertEqual(x.count, d.omega + d.k)
        let h1 = d.HintBitUnpack(x)
        XCTAssertEqual(h, h1)
    }

    func test() throws {
        doTest(Dilithium.D2)
        doTest(Dilithium.D3)
        doTest(Dilithium.D5)
    }

}
