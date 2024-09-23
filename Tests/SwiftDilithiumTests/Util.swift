//
//  File.swift
//  
//
//  Created by Leif Ibsen on 10/03/2024.
//

import Foundation
@testable import SwiftDilithium

struct Util {
    
    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            if b0 < 58 {
                bytes[i] = b0 - 48
            } else if b0 < 71 {
                bytes[i] = b0 - 65 + 10
            } else {
                bytes[i] = b0 - 97 + 10
            }
            bytes[i] <<= 4
            if b1 < 58 {
                bytes[i] |= b1 - 48
            } else if b1 < 71 {
                bytes[i] |= b1 - 65 + 10
            } else {
                bytes[i] |= b1 - 97 + 10
            }
        }
        return bytes
    }

    static func bytes2hex(_ x: Bytes, _ lowercase: Bool = true) -> String {
        let hexDigits = lowercase ?
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"] :
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }

    static func toInt(_ x: String) -> Int {
        var r = 0
        for s in x {
            r *= 10
            r += Int(s.asciiValue!) - 48
        }
        return r
    }

    struct katTest {
        // Key generation seed
        let xi: Bytes
        // Seed
        let seed: Bytes
        // Public key
        let pk: Bytes
        // Secret key
        let sk: Bytes
        // Message
        let msg: Bytes
        // Message length
        let mlen: Int
        // Signature + msg
        let sm: Bytes
        // Signature length
        let smlen: Int
    }
    
    static func makeKatTests(_ katTests: inout [katTest], _ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 10
        for i in 0 ..< groups {
            let j = i * 10
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(7)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(5)
            lines[j + 5].removeFirst(6)
            lines[j + 6].removeFirst(7)
            lines[j + 7].removeFirst(5)
            lines[j + 8].removeFirst(8)
        }
        for i in 0 ..< groups {
            let j = i * 10
            let xi = hex2bytes(lines[j + 1])
            let seed = hex2bytes(lines[j + 2])
            let pk = hex2bytes(lines[j + 3])
            let sk = hex2bytes(lines[j + 4])
            let msg = hex2bytes(lines[j + 5])
            let mlen = toInt(lines[j + 6])
            let sm = hex2bytes(lines[j + 7])
            let smlen = toInt(lines[j + 8])
            katTests.append(katTest(xi: xi, seed: seed, pk: pk, sk: sk, msg: msg, mlen: mlen, sm: sm, smlen: smlen))
        }
    }

    static func makeDilithium(_ kind: String) -> Dilithium {
        switch kind {
        case "DSA44":
            return Dilithium(.ML_DSA_44)
        case "DSA65":
            return Dilithium(.ML_DSA_65)
        case "DSA87":
            return Dilithium(.ML_DSA_87)
        default:
            fatalError("Wrong KATTEST kind " + kind)
        }
    }
    
}
