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

final class KAT87Test: XCTestCase {
    
    override func setUpWithError() throws {
        let url1 = Bundle.module.url(forResource: "kat87KeyGen", withExtension: "rsp")!
        Util.makeKeyGenTests(&keyGenTests, try Data(contentsOf: url1))
        let url2 = Bundle.module.url(forResource: "kat87Sign", withExtension: "rsp")!
        Util.makeSignTests(&signTests, try Data(contentsOf: url2))
        let url3 = Bundle.module.url(forResource: "kat87Verify", withExtension: "rsp")!
        Util.makeVerifyTests(&verifyTests, try Data(contentsOf: url3))
        let url4 = Bundle.module.url(forResource: "kat87HashSign", withExtension: "rsp")!
        Util.makeHashSignTests(&hashSignTests, try Data(contentsOf: url4))
        let url5 = Bundle.module.url(forResource: "kat87HashVerify", withExtension: "rsp")!
        Util.makeHashVerifyTests(&hashVerifyTests, try Data(contentsOf: url5))
    }
    
    var keyGenTests: [Util.keyGenTest] = []

    var signTests: [Util.signTest] = []

    var verifyTests: [Util.verifyTest] = []
    
    var hashSignTests: [Util.hashSignTest] = []

    var hashVerifyTests: [Util.hashVerifyTest] = []

    func testKeyGen() {
        Util.testKeyGen(.ML_DSA_87, keyGenTests)
    }

    func testSign() {
        Util.testSign(.ML_DSA_87, signTests)
    }

    func testVerify() {
        Util.testVerify(.ML_DSA_87, verifyTests)
    }

    func testHashSign() {
        Util.testHashSign(.ML_DSA_87, hashSignTests)
    }

    func testHashVerify() {
        Util.testHashVerify(.ML_DSA_87, hashVerifyTests)
    }

}
