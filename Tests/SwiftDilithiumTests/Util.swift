//
//  File.swift
//  
//
//  Created by Leif Ibsen on 10/03/2024.
//

import Foundation
import XCTest
@testable import SwiftDilithium
import Digest

struct Util {

    struct keyGenTest {
        let seed: Bytes
        let pk: Bytes
        let sk: Bytes
    }
    
    struct signTest {
        let message: Bytes
        let rnd: Bytes
        let sk: Bytes
        let context: Bytes
        let signature: Bytes
    }

    struct verifyTest {
        let testPassed: String
        let pk: Bytes
        let message: Bytes
        let context: Bytes
        let signature: Bytes
    }

    struct hashSignTest {
        let message: Bytes
        let sk: Bytes
        let context: Bytes
        let hashAlg: PreHash
        let signature: Bytes
    }

    struct hashVerifyTest {
        let testPassed: String
        let pk: Bytes
        let message: Bytes
        let context: Bytes
        let hashAlg: PreHash
        let signature: Bytes
    }

    static func makeKeyGenTests(_ tests: inout [keyGenTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 5
        for i in 0 ..< groups {
            let j = i * 5
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 5
            let seed = Base64.hex2bytes(lines[j + 1])!
            let pk = Base64.hex2bytes(lines[j + 2])!
            let sk = Base64.hex2bytes(lines[j + 3])!
            tests.append(keyGenTest(seed: seed, pk: pk, sk: sk))
        }
    }

    static func makeSignTests(_ tests: inout [signTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(10)
            lines[j + 2].removeFirst(Swift.min(lines[j + 2].count, 6))
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(Swift.min(lines[j + 4].count, 10))
            lines[j + 5].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let message = Base64.hex2bytes(lines[j + 1])!
            let rnd = lines[j + 2].count == 0 ? Bytes(repeating: 0, count: 32) : Base64.hex2bytes(lines[j + 2])!
            let sk = Base64.hex2bytes(lines[j + 3])!
            let context = Base64.hex2bytes(lines[j + 4])!
            let signature = Base64.hex2bytes(lines[j + 5])!
            tests.append(signTest(message: message, rnd: rnd, sk: sk, context: context, signature: signature))
        }
    }

    static func makeVerifyTests(_ tests: inout [verifyTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(13)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(10)
            lines[j + 4].removeFirst(Swift.min(lines[j + 4].count, 10))
            lines[j + 5].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let testPassed = lines[j + 1]
            let pk = Base64.hex2bytes(lines[j + 2])!
            let message = Base64.hex2bytes(lines[j + 3])!
            let context = Base64.hex2bytes(lines[j + 4])!
            let signature = Base64.hex2bytes(lines[j + 5])!
            tests.append(verifyTest(testPassed: testPassed, pk: pk, message: message, context: context, signature: signature))
        }
    }

    static func makeHashSignTests(_ tests: inout [hashSignTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(10)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(Swift.min(lines[j + 3].count, 10))
            lines[j + 4].removeFirst(10)
            lines[j + 5].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let message = Base64.hex2bytes(lines[j + 1])!
            let sk = Base64.hex2bytes(lines[j + 2])!
            let context = Base64.hex2bytes(lines[j + 3])!
            let hashAlg = preHash(lines[j + 4])
            let signature = Base64.hex2bytes(lines[j + 5])!
            tests.append(hashSignTest(message: message, sk: sk, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    static func makeHashVerifyTests(_ tests: inout [hashVerifyTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j + 1].removeFirst(13)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(10)
            lines[j + 4].removeFirst(Swift.min(lines[j + 4].count, 10))
            lines[j + 5].removeFirst(10)
            lines[j + 6].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let testPassed = lines[j + 1]
            let pk = Base64.hex2bytes(lines[j + 2])!
            let message = Base64.hex2bytes(lines[j + 3])!
            let context = Base64.hex2bytes(lines[j + 4])!
            let hashAlg = preHash(lines[j + 5])
            let signature = Base64.hex2bytes(lines[j + 6])!
            tests.append(hashVerifyTest(testPassed: testPassed, pk: pk, message: message, context: context, hashAlg: hashAlg, signature: signature))
        }
    }
    
    static func preHash(_ hashAlg: String) -> PreHash {
        if hashAlg == "SHA2-224" {
            return .SHA2_224
        }
        if hashAlg == "SHA2-256" {
            return .SHA2_256
        }
        if hashAlg == "SHA2-384" {
            return .SHA2_384
        }
        if hashAlg == "SHA2-512" {
            return .SHA2_512
        }
        if hashAlg == "SHA3-224" {
            return .SHA3_224
        }
        if hashAlg == "SHA3-256" {
            return .SHA3_256
        }
        if hashAlg == "SHA3-384" {
            return .SHA3_384
        }
        if hashAlg == "SHA3-512" {
            return .SHA3_512
        }
        if hashAlg == "SHAKE-128" {
            return .SHAKE128
        }
        if hashAlg == "SHAKE-256" {
            return .SHAKE256
        }
        fatalError("Wrong hash algorithm: \(hashAlg)")
    }
    
    static func testKeyGen(_ kind: Kind, _ tests: [keyGenTest]) {
        let dilithium = Dilithium(kind)
        for t in tests {
            let (pk, sk) = dilithium.KeyGenInternal(t.seed)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
        }
    }
    
    static func testSign(_ kind: Kind, _ tests: [signTest]) {
        let dilithium = Dilithium(kind)
        for t in tests {
            let rho = Bytes(t.sk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let signature = dilithium.SignInternal(t.sk, [0] + [Byte(t.context.count)] + t.context + t.message, t.rnd, aHat)
            XCTAssertEqual(signature, t.signature)
        }
    }
    
    static func testVerify(_ kind: Kind, _ tests: [verifyTest]) {
        let dilithium = Dilithium(kind)
        for t in tests {
            let rho = Bytes(t.pk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let ok = dilithium.VerifyInternal(t.pk, [0] + [Byte(t.context.count)] + t.context + t.message, t.signature, aHat)
            XCTAssertEqual(t.testPassed, ok ? "true" : "false")
        }
    }
    
    static func testHashSign(_ kind: Kind, _ tests: [hashSignTest]) {
        let dilithium = Dilithium(kind)
        for t in tests {
            let rho = Bytes(t.sk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let signature = dilithium.hashSign(t.sk, t.message, t.context, t.hashAlg, false, aHat)
            XCTAssertEqual(signature, t.signature)
        }
    }
    
    static func testHashVerify(_ kind: Kind, _ tests: [hashVerifyTest]) {
        let dilithium = Dilithium(kind)
        for t in tests {
            let rho = Bytes(t.pk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let ok = dilithium.hashVerify(t.pk, t.message, t.signature, t.context, t.hashAlg, aHat)
            XCTAssertEqual(t.testPassed, ok ? "true" : "false")
        }
    }

}
