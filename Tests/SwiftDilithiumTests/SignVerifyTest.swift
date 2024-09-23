//
//  SignVerifyTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class SignVerifyTest: XCTestCase {

    func doTest(_ kind: Kind) throws {
        for _ in 0 ..< 5 {
            var msg = Dilithium.randomBytes(1000)
            let (secretKey, publicKey) = Dilithium.GenerateKeyPair(kind: kind)
            var sig1 = secretKey.Sign(message: msg, randomize: true)
            var sig2 = secretKey.Sign(message: msg, randomize: false)
            XCTAssertTrue(publicKey.Verify(message: msg, signature: sig1))
            XCTAssertTrue(publicKey.Verify(message: msg, signature: sig2))
            msg[0] &+= 1
            XCTAssertFalse(publicKey.Verify(message: msg, signature: sig1))
            XCTAssertFalse(publicKey.Verify(message: msg, signature: sig2))
            msg[0] &-= 1
            sig1[0] &+= 1
            sig2[0] &+= 1
            XCTAssertFalse(publicKey.Verify(message: msg, signature: sig1))
            XCTAssertFalse(publicKey.Verify(message: msg, signature: sig2))
        }
    }

    func test() throws {
        try doTest(.ML_DSA_44)
        try doTest(.ML_DSA_65)
        try doTest(.ML_DSA_87)
    }

}
