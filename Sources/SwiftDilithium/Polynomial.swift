//
//  Polynomial.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 03/11/2023.
//

struct Polynomial: Equatable {

    // 1753 ^ BitRev8(k) % Q for k in 1 ..< 256
    // From [FIPS 204] - Appendix B
    static let zetas = [
                0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
          7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
          5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
          5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
          3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
           394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
          3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
          5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
          3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
          2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
          1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
          4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
          5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
          7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
          1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
           348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
             1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
          1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
          8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
          6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
          4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
          3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
          2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
          7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
          6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
          6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
          5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
          3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
          3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
          3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
          6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
          8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983
    ]

    var coef: [Int]
    
    init() {
        self.coef = [Int](repeating: 0, count: 256)
    }
    
    init(_ coef: [Int]) {
        assert(coef.count == 256)
        self.coef = coef
    }

    // [FIPS 204] - Algorithm 41, Number Theoretic Transform
    func NTT() -> Polynomial {
        var w = self.coef
        var m = 0
        var len = 128
        w.withUnsafeMutableBufferPointer { wU in
            while len >= 1 {
                var start = 0
                while start < 256 {
                    m += 1
                    let z = Polynomial.zetas[m]
                    for j in start ..< start + len {
                        let t = Dilithium.modQ(z * wU[j + len])
                        wU[j + len] = Dilithium.modQ(wU[j] - t)
                        wU[j] = Dilithium.modQ(wU[j] + t)
                    }
                    start += len << 1
                }
                len >>= 1
            }
        }
        return Polynomial(w)
    }

    // [FIPS 204] - Algorithm 42, Inverse Number Theoretic Transform
    func INTT() -> Polynomial {
        var w = self.coef
        var m = 256
        var len = 1
        w.withUnsafeMutableBufferPointer { wU in
            while len < 256 {
                var start = 0
                while start < 256 {
                    m -= 1
                    let z = -Polynomial.zetas[m]
                    for j in start ..< start + len {
                        let t = wU[j]
                        wU[j] = Dilithium.modQ(t + wU[j + len])
                        wU[j + len] = Dilithium.modQ(t - wU[j + len])
                        wU[j + len] = Dilithium.modQ(z * wU[j + len])
                    }
                    start += len << 1
                }
                len <<= 1
            }
            for j in 0 ..< 256 {
                wU[j] = Dilithium.modQ(wU[j] * 8347681)  // 8347681 = 256^-1 mod Q
            }
        }
        return Polynomial(w)
    }

    func modPMQ() -> Polynomial {
        var p = Polynomial()
        for i in 0 ..< 256 {
            p.coef[i] = Dilithium.modPMQ(self.coef[i])
        }
        return p
    }

    func OneCount() -> Int {
        var x = 0
        for i in 0 ..< 256 {
            if self.coef[i] == 1 {
                x += 1
            }
        }
        return x
    }
    
    func checkNorm(_ limit: Int) -> Bool {
        for i in 0 ..< 256 {
            if Swift.abs(Dilithium.modPMQ(self.coef[i])) >= limit {
                return true
            }
        }
        return false
    }

    // p1 * p2
    static func *(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = Dilithium.modQ(p1.coef[i] * p2.coef[i])
        }
        return Polynomial(x)
    }

    // p1 + p2
    static func +(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var sum = p1
        for i in 0 ..< Dilithium.N {
            sum.coef[i] += p2.coef[i]
        }
        return sum
    }

    // p1 += p2
    static func +=(_ p1: inout Polynomial, _ p2: Polynomial) {
        p1 = p1 + p2
    }

    // -p
    static prefix func -(p: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = -p.coef[i]
        }
        return Polynomial(x)
    }

    // p1 - p2
    static func -(_ p1: Polynomial, _ p2: Polynomial) -> Polynomial {
        var diff = p1
        for i in 0 ..< Dilithium.N {
            diff.coef[i] -= p2.coef[i]
        }
        return diff
    }

    // p1 -= p2
    static func -=(_ p1: inout Polynomial, _ p2: Polynomial) {
        p1 = p1 - p2
    }

    // p * d
    static func *(_ p: Polynomial, _ d: Int) -> Polynomial {
        var x = Polynomial()
        for i in 0 ..< p.coef.count {
            x.coef[i] = (p.coef[i] * d) % Dilithium.Q
        }
        return x
    }

}
