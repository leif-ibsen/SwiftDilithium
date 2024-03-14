//
//  BitPacktest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class BitPacktest: XCTestCase {

    func test() throws {
        var w = Polynomial()
        for bl in 1 ..< 63 {
            let b = 1 << bl
            for i in 0 ..< 256 {
                w.coef[i] = Int.random(in: 0 ... b)
            }
            let bytes = Dilithium.SimpleBitPack(w, b)
            XCTAssertEqual(bytes.count, Dilithium.bitlen(b) * 32)
            let w1 = Dilithium.SimpleBitUnpack(bytes, b)
            XCTAssertEqual(w1, w)
        }
        for bl in 1 ..< 32 {
            let a = (1 << bl - 1)
            let b = (1 << bl - 1)
            for i in 0 ..< 256 {
                w.coef[i] = Int.random(in: -a ... b)
            }
            let bytes = Dilithium.BitPack(w, a, b)
            XCTAssertEqual(bytes.count, Dilithium.bitlen(a + b) * 32)
            let w1 = Dilithium.BitUnpack(bytes, a, b)
            XCTAssertEqual(w1, w)
        }
    }

}
