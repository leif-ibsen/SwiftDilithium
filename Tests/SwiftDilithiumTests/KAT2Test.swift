//
//  KAT2Test.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class KAT2Test: XCTestCase {

    // Test vectors from https://github.com/post-quantum-cryptography/KAT

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "kat2", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        for t in katTests {
            let (pk, sk) = Dilithium.D2.KeyGen(t.xi)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
            let sig = Dilithium.D2.Sign(sk, t.msg)
            XCTAssertEqual(sig + t.msg, t.sm)
            XCTAssertEqual(t.msg.count, t.mlen)
            XCTAssertEqual(sig.count + t.msg.count, t.smlen)
        }
    }

}
