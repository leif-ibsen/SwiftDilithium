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

final class KATTestKeyGen: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyGen", withExtension: "rsp")!
        makeKeyGenTests(try Data(contentsOf: url))
    }
    
    struct keyGenTest {
        let tcId: String
        let kind: Kind
        let seed: Bytes
        let pk: Bytes
        let sk: Bytes
    }

    var keyGenTests: [keyGenTest] = []

    func makeKeyGenTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 6
        for i in 0 ..< groups {
            let j = i * 6
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(7)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 6
            let tcId = lines[j]
            let kind = Util.dilithiumKind(lines[j + 1])
            let seed = Base64.hex2bytes(lines[j + 2])!
            let pk = Base64.hex2bytes(lines[j + 3])!
            let sk = Base64.hex2bytes(lines[j + 4])!
            keyGenTests.append(keyGenTest(tcId: tcId, kind: kind, seed: seed, pk: pk, sk: sk))
        }
    }

    func testKeyGen() {
        for t in keyGenTests {
            let dilithium = Dilithium(t.kind)
            let (pk, sk) = dilithium.KeyGenInternal(t.seed)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
        }
    }
}
