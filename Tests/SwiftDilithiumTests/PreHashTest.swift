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
        let (sk, pk) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)
        let sig = sk.Sign(message: msg, ph: .SHA256)
        XCTAssertTrue(pk.Verify(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHA512() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)
        let sig = sk.Sign(message: msg, ph: .SHA512)
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA256))
        XCTAssertTrue(pk.Verify(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHAKE128() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)
        let sig = sk.Sign(message: msg, ph: .SHAKE128)
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA512))
        XCTAssertTrue(pk.Verify(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE256))
    }

    func testSHAKE256() throws {
        let msg = Dilithium.randomBytes(100)
        let (sk, pk) = Dilithium.GenerateKeyPair(kind: .ML_DSA_44)
        let sig = sk.Sign(message: msg, ph: .SHAKE256)
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA256))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHA512))
        XCTAssertFalse(pk.Verify(message: msg, signature: sig, ph: .SHAKE128))
        XCTAssertTrue(pk.Verify(message: msg, signature: sig, ph: .SHAKE256))
    }

}
