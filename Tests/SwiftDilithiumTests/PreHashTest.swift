//
//  PreHashTest.swift
//  
//
//  Created by Leif Ibsen on 29/08/2024.
//

import XCTest
@testable import SwiftDilithium

final class PreHashTest: XCTestCase {

    func testSHA256() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.ML_DSA_44.GenerateKeyPair()
        let sig = sk.SignPrehash(message: msg, ph: .SHA256)
        XCTAssertTrue(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHA512() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.ML_DSA_44.GenerateKeyPair()
        let sig = sk.SignPrehash(message: msg, ph: .SHA512)
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA256))
        XCTAssertTrue(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHAKE128() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.ML_DSA_44.GenerateKeyPair()
        let sig = sk.SignPrehash(message: msg, ph: .SHAKE128)
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA512))
        XCTAssertTrue(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHAKE256() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.ML_DSA_44.GenerateKeyPair()
        let sig = sk.SignPrehash(message: msg, ph: .SHAKE256)
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertTrue(pk.VerifyPrehash(message: msg, signature: sig, ph: .SHAKE256))
    }

}
