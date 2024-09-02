//
//  ContextTest.swift
//  
//
//  Created by Leif Ibsen on 29/08/2024.
//

import XCTest
@testable import SwiftDilithium

final class ContextTest: XCTestCase {

    func doTest(_ d: Dilithium) throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = d.GenerateKeyPair()
        XCTAssertTrue(try pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: []), context: []))
        XCTAssertTrue(try pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: [1]), context: [1]))
        XCTAssertFalse(try pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: []), context: [1]))
        XCTAssertFalse(try pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: [1]), context: []))
    }

    func test() throws {
        try doTest(Dilithium.ML_DSA_44)
        try doTest(Dilithium.ML_DSA_65)
        try doTest(Dilithium.ML_DSA_87)
    }

}
