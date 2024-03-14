//
//  EncodeDecodeTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class EncodeDecodeTest: XCTestCase {
    
    func doTest(_ d: Dilithium) {
        let (pk, sk) = d.KeyGen()
        let (rhox, t1x) = d.pkDecode(pk)
        let pk1 = d.pkEncode(rhox, t1x)
        XCTAssertEqual(pk, pk1)
        let (rho, K, tr, s1, s2, t0) = d.skDecode(sk)
        let sk1 = d.skEncode(rho, K, tr, s1, s2, t0)
        XCTAssertEqual(sk, sk1)
    }
    
    func test() throws {
        for _ in 0 ..< 10 {
            doTest(Dilithium.D2)
            doTest(Dilithium.D3)
            doTest(Dilithium.D5)
        }
    }
    
}
