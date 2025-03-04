//
//  PEMTest.swift
//  
//
//  Created by Leif Ibsen on 05/09/2024.
//

import XCTest
@testable import SwiftDilithium

final class PEMTest: XCTestCase {

    func doTest(_ kind: Kind) throws {
        let (sk, pk) = Dilithium.GenerateKeyPair(kind: kind)
        let pk1 = try PublicKey(pem: pk.pem)
        let sk1 = try SecretKey(pem: sk.pem)
        XCTAssertEqual(pk, pk1)
        XCTAssertEqual(pk.aHat, pk1.aHat)
        XCTAssertEqual(sk, sk1)
        XCTAssertEqual(sk.aHat, sk1.aHat)
    }

    func test() throws {
        try doTest(.ML_DSA_44)
        try doTest(.ML_DSA_65)
        try doTest(.ML_DSA_87)
    }

}
