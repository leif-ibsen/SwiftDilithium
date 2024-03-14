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
        let keyBytes = Bytes(repeating: 0, count: 100)
        do {
            _ = try PublicKey(keyBytes: keyBytes)
            XCTFail("Expected publicKeySize exception")
        } catch DilithiumException.publicKeySize {
        } catch {
            XCTFail("Expected publicKeySize exception")
        }
        do {
            _ = try SecretKey(keyBytes: keyBytes)
            XCTFail("Expected secretKeySize exception")
        } catch DilithiumException.secretKeySize {
        } catch {
            XCTFail("Expected secretKeySize exception")
        }
    }

    func test() throws {
        doTest(Dilithium.D2)
        doTest(Dilithium.D3)
        doTest(Dilithium.D5)
    }

}
