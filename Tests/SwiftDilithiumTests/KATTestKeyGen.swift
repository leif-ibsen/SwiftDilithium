//
//  KATTestKeyGen.swift
//  
//
//  Created by Leif Ibsen on 28/08/2024.
//

import XCTest
@testable import SwiftDilithium

// KAT test vectors from GitHub ACVP-server release 1.1.0.35.
final class KATTestKeyGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyGen", withExtension: "rsp")!
        makeKatTests(try Data(contentsOf: url))
    }

    struct katTest {
        let kind: String
        let seed: Bytes
        let pk: Bytes
        let sk: Bytes
    }
    
    var katTests: [katTest] = []
    
    func makeKatTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 6
        for i in 0 ..< groups {
            let j = i * 6
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(3)
            lines[j + 4].removeFirst(3)
        }
        for i in 0 ..< groups {
            let j = i * 6
            let kind = lines[j + 1]
            let seed = Util.hex2bytes(lines[j + 2])
            let pk = Util.hex2bytes(lines[j + 3])
            let sk = Util.hex2bytes(lines[j + 4])
            katTests.append(katTest(kind: kind, seed: seed, pk: pk, sk: sk))
        }
    }

    func test() throws {
        for t in katTests {
            let dilithium = Util.makeDilithium(t.kind)
            let (pk, sk) = dilithium.KeyGenInternal(t.seed)
            XCTAssertEqual(pk, t.pk)
            XCTAssertEqual(sk, t.sk)
        }
    }

}
