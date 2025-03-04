//
//  KATTestSign.swift
//  
//
//  Created by Leif Ibsen on 28/08/2024.
//

import XCTest
@testable import SwiftDilithium

// KAT test vectors from GitHub ACVP-server release 1.1.0.35.
final class KATTestSign: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSign", withExtension: "rsp")!
        makeKatTests(try Data(contentsOf: url))
    }

    struct katTest {
        let kind: String
        let sk: Bytes
        let message: Bytes
        let rnd: Bytes
        let signature: Bytes
    }
    
    var katTests: [katTest] = []
    let b32 = Bytes(repeating: 0, count: 32)

    func makeKatTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(3)
            lines[j + 3].removeFirst(8)
            lines[j + 4].removeFirst(4)
            lines[j + 5].removeFirst(10)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let kind = lines[j + 1]
            let sk = Util.hex2bytes(lines[j + 2])
            let message = Util.hex2bytes(lines[j + 3])
            let rnd = lines[j + 4].count == 0 ? b32 : Util.hex2bytes(lines[j + 4])
            let signature = Util.hex2bytes(lines[j + 5])
            katTests.append(katTest(kind: kind, sk: sk, message: message, rnd: rnd, signature: signature))
        }
    }

    func test() throws {
        for t in katTests {
            let dilithium = Util.makeDilithium(t.kind)
            let rho = Bytes(t.sk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let signature = dilithium.SignInternal(t.sk, t.message, t.rnd, aHat)
            XCTAssertEqual(signature, t.signature)
        }
    }

}
