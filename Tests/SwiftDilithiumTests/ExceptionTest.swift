//
//  ExceptionTest.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium

final class ExceptionTest: XCTestCase {

    func doTest(_ kind: Kind) {
        let keySize = 100
        let keyBytes = Bytes(repeating: 0, count: keySize)
        do {
            _ = try PublicKey(keyBytes: keyBytes)
            XCTFail("Expected publicKeySize exception")
        } catch Exception.publicKeySize(let value) {
            XCTAssertEqual(value, keySize)
        } catch {
            XCTFail("Expected publicKeySize exception")
        }
        do {
            _ = try SecretKey(keyBytes: keyBytes)
            XCTFail("Expected secretKeySize exception")
        } catch Exception.secretKeySize(let value) {
            XCTAssertEqual(value, keySize)
        } catch {
            XCTFail("Expected secretKeySize exception")
        }
        do {
            let (sk, _) = Dilithium.GenerateKeyPair(kind: kind)
            _ = try sk.Sign(message: [], context: Bytes(repeating: 0, count: 256))
            XCTFail("Expected contextSize exception")
        } catch Exception.contextSize(let value) {
            XCTAssertEqual(value, 256)
        } catch {
            XCTFail("Expected contextSize exception")
        }
    }

    func test() throws {
        doTest(.ML_DSA_44)
        doTest(.ML_DSA_65)
        doTest(.ML_DSA_87)
    }

}
