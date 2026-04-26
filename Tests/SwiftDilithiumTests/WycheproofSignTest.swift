//
//  KAT44Test.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 20/03/2025.
//

import XCTest
@testable import SwiftDilithium
import Digest

// Test vectors from the Wycheproof project, mldsa_44_sign_seed_test, mldsa_65_sign_seed_test and mldsa_87_sign_seed_test

final class WycheproofSignTest: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "wycheproofSign", withExtension: "rsp")!
        makeSignTests(try Data(contentsOf: url))
    }

    struct signTest {
        let tcId: String
        let message: Bytes
        let context: Bytes
        let signature: Bytes
    }

    struct testGroup {
        let kind: Kind
        let seed: Bytes
        var tests: [signTest]
    }

    var testGroups: [testGroup] = []

    func makeSignTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        var i = 0
        while i < lines.count {
            lines[i].removeFirst(7)
            lines[i + 1].removeFirst(7)
            lines[i + 2].removeFirst(8)
            let kind = Util.dilithiumKind(lines[i])
            let seed = Base64.hex2bytes(lines[i + 1])!
            let tests = Int(lines[i + 2])!
            var group = testGroup(kind: kind, seed: seed, tests: [])
            i += 4
            for _ in 0 ..< tests {
                lines[i].removeFirst(7)
                lines[i + 1].removeFirst(10)
                lines[i + 2].removeFirst(10)
                lines[i + 3].removeFirst(12)
                let tcId = lines[i]
                let message = Base64.hex2bytes(lines[i + 1])!
                let context = Base64.hex2bytes(lines[i + 2])!
                let signature = Base64.hex2bytes(lines[i + 3])!
                group.tests.append(signTest(tcId: tcId, message: message, context: context, signature: signature))
                i += 5
            }
            testGroups.append(group)
        }
    }

    func testSign() throws {
        for tg in testGroups {
            let dilithium = Dilithium(tg.kind)
            let (_, sk) = dilithium.KeyGenInternal(tg.seed)
            let sKey = SecretKey(sk, dilithium)
            for t in tg.tests {
                let signature = try sKey.Sign(message: t.message, context: t.context, randomize: false)
                XCTAssertEqual(signature, t.signature)
            }
        }
    }

}
