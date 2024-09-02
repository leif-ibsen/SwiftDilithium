//
//  ExceptionTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class ExceptionTest: XCTestCase {

    func doTest(_ d: Dilithium) {
        let keySize = 100
        let keyBytes = Bytes(repeating: 0, count: keySize)
        do {
            _ = try PublicKey(keyBytes: keyBytes)
            XCTFail("Expected publicKeySize exception")
        } catch DilithiumException.publicKeySize(let value) {
            XCTAssertEqual(value, keySize)
        } catch {
            XCTFail("Expected publicKeySize exception")
        }
        do {
            _ = try SecretKey(keyBytes: keyBytes)
            XCTFail("Expected secretKeySize exception")
        } catch DilithiumException.secretKeySize(let value) {
            XCTAssertEqual(value, keySize)
        } catch {
            XCTFail("Expected secretKeySize exception")
        }
        do {
            let (sk, _) = d.GenerateKeyPair()
            _ = try sk.Sign(message: [], context: Bytes(repeating: 0, count: 256))
            XCTFail("Expected contextSize exception")
        } catch DilithiumException.contextSize(let value) {
            XCTAssertEqual(value, 256)
        } catch {
            XCTFail("Expected contextSize exception")
        }
    }

    func test() throws {
        doTest(Dilithium.ML_DSA_44)
        doTest(Dilithium.ML_DSA_65)
        doTest(Dilithium.ML_DSA_87)
    }

}
