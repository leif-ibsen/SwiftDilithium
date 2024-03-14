//
//  SignVerifyTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class SignVerifyTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        for _ in 0 ..< 10 {
            var msg = Bytes(repeating: 0, count: 1000)
            Dilithium.randomBytes(&msg)
            let (secretKey, publicKey) = d.GenerateKeyPair()
            var sig1 = secretKey.Sign(message: msg, deterministic: true)
            var sig2 = secretKey.Sign(message: msg, deterministic: false)
            XCTAssertTrue(publicKey.Verify(signature: sig1, message: msg))
            XCTAssertTrue(publicKey.Verify(signature: sig2, message: msg))
            msg[0] &+= 1
            XCTAssertFalse(publicKey.Verify(signature: sig1, message: msg))
            XCTAssertFalse(publicKey.Verify(signature: sig2, message: msg))
            msg[0] &-= 1
            sig1[0] &+= 1
            sig2[0] &+= 1
            XCTAssertFalse(publicKey.Verify(signature: sig1, message: msg))
            XCTAssertFalse(publicKey.Verify(signature: sig2, message: msg))
        }
    }

    func test() throws {
        doTest(Dilithium.D2)
        doTest(Dilithium.D3)
        doTest(Dilithium.D5)
    }

}
