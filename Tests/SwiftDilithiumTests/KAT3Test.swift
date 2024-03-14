//
//  KAT3Test.swift
//  
//
//  Created by Leif Ibsen on 12/03/2024.
//

import XCTest
@testable import SwiftDilithium
import Digest

final class KAT3Test: XCTestCase {
    
    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "kat3", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }
    
    var katTests: [Util.katTest] = []
    
    func test() throws {
        let md = MessageDigest(.SHA2_256)
        for t in katTests {
            let (pk, sk) = Dilithium.D3.KeyGen(t.seed)
            XCTAssertEqual(md.digest(pk), t.pkDigest)
            XCTAssertEqual(md.digest(sk), t.skDigest)
        }
    }

}
