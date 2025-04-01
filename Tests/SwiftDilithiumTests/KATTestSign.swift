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

final class KATTestSign: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSign", withExtension: "rsp")!
        makeSignTests(try Data(contentsOf: url))
    }
    
    struct signTest {
        let tcId: String
        let kind: Kind
        let interface: String
        let message: Bytes
        let rnd: Bytes
        let sk: Bytes
        let context: Bytes
        let hashAlg: PreHash?
        let signature: Bytes
    }

    var signTests: [signTest] = []

    func makeSignTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 10
        for i in 0 ..< groups {
            let j = i * 10
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(12)
            lines[j + 3].removeFirst(10)
            lines[j + 4].removeFirst(Swift.min(lines[j + 4].count, 6))
            lines[j + 5].removeFirst(5)
            lines[j + 6].removeFirst(Swift.min(lines[j + 6].count, 10))
            lines[j + 7].removeFirst(10)
            lines[j + 8].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 10
            let tcId = lines[j]
            let kind = Util.dilithiumKind(lines[j + 1])
            let interface = lines[j + 2]
            let message = Base64.hex2bytes(lines[j + 3])!
            let rnd = lines[j + 4].count == 0 ? Bytes(repeating: 0, count: 32) : Base64.hex2bytes(lines[j + 4])!
            let sk = Base64.hex2bytes(lines[j + 5])!
            let context = Base64.hex2bytes(lines[j + 6])!
            let hashAlg = Util.preHash(lines[j + 7])
            let signature = Base64.hex2bytes(lines[j + 8])!
            signTests.append(signTest(tcId: tcId, kind: kind, interface: interface, message: message, rnd: rnd, sk: sk, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    func testSign() {
        for t in signTests {
            let dilithium = Dilithium(t.kind)
            let rho = Bytes(t.sk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            var signature: Bytes
            if t.hashAlg == nil {
                if t.interface == "internal" {
                    signature = dilithium.SignInternal(t.sk, t.message, t.rnd, aHat)
                } else {
                    signature = dilithium.Sign(t.sk, t.message, t.context, false, aHat)
                }
            } else {
                signature = dilithium.hashSign(t.sk, t.message, t.context, t.hashAlg!, false, aHat)
            }
            XCTAssertEqual(signature, t.signature)
        }
    }

}
