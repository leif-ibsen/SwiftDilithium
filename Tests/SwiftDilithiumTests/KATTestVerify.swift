//
//  KATTestVerify.swift
//  
//
//  Created by Leif Ibsen on 28/08/2024.
//

import XCTest
@testable import SwiftDilithium

// KAT test vectors from GitHub ACVP-server release 1.1.0.35.
final class KATTestVerify: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestVerify", withExtension: "rsp")!
        makeKatTests(try Data(contentsOf: url))
    }

    struct katTest {
        let kind: String
        let pass: String
        let pk: Bytes
        let message: Bytes
        let signature: Bytes
    }
    
    var katTests: [katTest] = []

    func makeKatTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(3)
            lines[j + 4].removeFirst(8)
            lines[j + 5].removeFirst(10)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let kind = lines[j + 1]
            let pass = lines[j + 2]
            let pk = Util.hex2bytes(lines[j + 3])
            let message = Util.hex2bytes(lines[j + 4])
            let signature = Util.hex2bytes(lines[j + 5])
            katTests.append(katTest(kind: kind, pass: pass, pk: pk, message: message, signature: signature))
        }
    }

    func test() throws {
        for t in katTests {
            let dilithium = Util.makeDilithium(t.kind)
            let rho = Bytes(t.pk[0 ..< 32])
            let aHat = dilithium.ExpandA(rho)
            let ok = dilithium.VerifyInternal(t.pk, t.message, t.signature, aHat)
            if ok {
                XCTAssertEqual(t.pass, "true")
            } else {
                XCTAssertEqual(t.pass, "false")
            }
        }
    }

}
