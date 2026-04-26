//
//  KAT44Test.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 20/03/2025.
//

import XCTest
@testable import SwiftDilithium
import Digest

// Test vectors from the Wycheproof project, mldsa_44_verify_test, mldsa_65_verify_test and mldsa_87_verify_test

final class WycheproofVerifyTest: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "wycheproofVerify", withExtension: "rsp")!
        makeVerifyTests(try Data(contentsOf: url))
    }

    struct verifyTest {
        let tcId: String
        let testPassed: Bool
        let message: Bytes
        let context: Bytes
        let signature: Bytes
    }
    
    struct testGroup {
        let kind: Kind
        let pk: Bytes
        var tests: [verifyTest]
    }
    
    var testGroups: [testGroup] = []

    func makeVerifyTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        var i = 0
        while i < lines.count {
            lines[i].removeFirst(7)
            lines[i + 1].removeFirst(5)
            lines[i + 2].removeFirst(8)
            let kind = Util.dilithiumKind(lines[i])
            let pk = Base64.hex2bytes(lines[i + 1])!
            let tests = Int(lines[i + 2])!
            var group = testGroup(kind: kind, pk: pk, tests: [])
            i += 4
            for _ in 0 ..< tests {
                lines[i].removeFirst(7)
                lines[i + 1].removeFirst(13)
                lines[i + 2].removeFirst(10)
                lines[i + 3].removeFirst(10)
                lines[i + 4].removeFirst(12)

                let tcId = lines[i]
                let testPassed = lines[i + 1] == "true"
                let message = Base64.hex2bytes(lines[i + 2])!
                let context = Base64.hex2bytes(lines[i + 3])!
                let signature = Base64.hex2bytes(lines[i + 4])!
                group.tests.append(verifyTest(tcId: tcId, testPassed: testPassed, message: message, context: context, signature: signature))
                i += 6
            }
            testGroups.append(group)
        }        
    }

    func testVerify() throws {
        for tg in testGroups {
            let pk = try PublicKey(keyBytes: tg.pk)
            for t in tg.tests {
                let ok = pk.Verify(message: t.message, signature: t.signature, context: t.context)
                XCTAssertEqual(t.testPassed, ok)
            }
        }
    }

}
