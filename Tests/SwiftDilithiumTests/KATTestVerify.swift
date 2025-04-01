//
//  KAT44Test.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 20/03/2025.
//

import XCTest
@testable import SwiftDilithium
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestVerify: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestVerify", withExtension: "rsp")!
        makeVerifyTests(try Data(contentsOf: url))
    }

    struct verifyTest {
        let tcId: String
        let kind: Kind
        let interface: String
        let testPassed: Bool
        let pk: Bytes
        let message: Bytes
        let context: Bytes
        let hashAlg: PreHash?
        let signature: Bytes
    }

    var verifyTests: [verifyTest] = []

    func makeVerifyTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 10
        for i in 0 ..< groups {
            let j = i * 10
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(12)
            lines[j + 3].removeFirst(13)
            lines[j + 4].removeFirst(5)
            lines[j + 5].removeFirst(10)
            lines[j + 6].removeFirst(Swift.min(lines[j + 6].count, 10))
            lines[j + 7].removeFirst(10)
            lines[j + 8].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 10
            let tcId = lines[j]
            let kind = Util.dilithiumKind(lines[j + 1])
            let interface = lines[j + 2]
            let testPassed = lines[j + 3] == "true"
            let pk = Base64.hex2bytes(lines[j + 4])!
            let message = Base64.hex2bytes(lines[j + 5])!
            let context = Base64.hex2bytes(lines[j + 6])!
            let hashAlg = Util.preHash(lines[j + 7])
            let signature = Base64.hex2bytes(lines[j + 8])!
            verifyTests.append(verifyTest(tcId: tcId, kind: kind, interface: interface, testPassed: testPassed, pk: pk, message: message, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    func testVerify() {
        for t in verifyTests {
            let dilithium = Dilithium(t.kind)
            let rho = Bytes(t.pk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            var ok: Bool
            if t.hashAlg == nil {
                if t.interface == "internal" {
                    ok = dilithium.VerifyInternal(t.pk, t.message, t.signature, aHat)
                } else {
                    ok = dilithium.Verify(t.pk, t.message, t.signature, t.context, aHat)
                }
            } else {
                ok = dilithium.hashVerify(t.pk, t.message, t.signature, t.context, t.hashAlg!, aHat)
            }
            XCTAssertEqual(t.testPassed, ok)
        }
    }

}
