//
//  HintBitTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class HintBitTest: XCTestCase {

    func doTest(_ kind: Kind) {
        let d = Dilithium(kind)
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
        doTest(.ML_DSA_44)
        doTest(.ML_DSA_65)
        doTest(.ML_DSA_87)
    }

}
