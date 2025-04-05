//
//  Dilithium.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 01/11/2023.
//

import Foundation
import ASN1
import Digest

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

public struct Dilithium {
    

    // MARK: Static Methods

    /// Generates a secret key and a public key
    ///
    /// - Parameters:
    ///   - kind: The Dilithium kind
    /// - Returns: The secret key `sk` and the public key `pk`
    public static func GenerateKeyPair(kind: Kind) -> (sk: SecretKey, pk: PublicKey) {
        let dilithium = Dilithium(kind)
        let (pk, sk) = dilithium.KeyGen()
        return (SecretKey(sk, dilithium), PublicKey(pk, dilithium))
    }

    static func randomBytes(_ n: Int) -> Bytes {
        var bytes = Bytes(repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
        return bytes
    }

    static let BLANK = Int.max
    static let Q = 8380417    // modulus
    static let Q2 = 4190208   // Q / 2
    static let D = 13         // dropped bits from t
    static let N = 256        // polynomial size

    let tau: Int
    let entr: Int
    let lambda: Int
    let gamma1: Int
    let gamma2: Int
    let k: Int
    let l: Int
    let eta: Int
    let beta: Int
    let omega: Int
    let sigSize: Int
    let pkSize: Int
    let skSize: Int
    let oid: ASN1ObjectIdentifier

    init(_ kind: Kind) {
        let param = Parameters.paramsFromKind(kind)
        self.tau = param.tau
        self.entr = param.entr
        self.lambda = param.lambda
        self.gamma1 = param.gamma1
        self.gamma2 = param.gamma2
        self.k = param.k
        self.l = param.l
        self.eta = param.eta
        self.beta = param.beta
        self.omega = param.omega
        self.sigSize = param.sigSize
        self.pkSize = param.pkSize
        self.skSize = param.skSize
        self.oid = param.oid
    }

    static func bitlen(_ x: Int) -> Int {
        assert(x > 0)
        return 64 - x.leadingZeroBitCount
    }
    
    static func mod(_ x: Int, _ m: Int) -> Int {
        assert(m > 0)
        let t = x % m
        return t < 0 ? t + m : t
    }

    static func modQ(_ x: Int) -> Int {
        assert(-(Dilithium.Q * Dilithium.Q) < x && x < Dilithium.Q * Dilithium.Q)
        let t = x % Dilithium.Q
        return t < 0 ? t + Dilithium.Q : t
    }

    // [FIPS 204] - section 2.3
    static func modPM(_ r: Int, _ a: Int) -> Int {
        let t = r % a
        if t > a / 2 {
            return t - a
        } else if t < -a / 2 {
            return t + a
        } else {
            return t
        }
    }

    static func modPMQ(_ r: Int) -> Int {
        let t = r % Dilithium.Q
        if t > Dilithium.Q2 {
            return t - Dilithium.Q
        } else if t < -Dilithium.Q2 {
            return t + Dilithium.Q
        } else {
            return t
        }
    }

    // [FIPS 204] - Algorithm 1
    func KeyGen() -> (pk: Bytes, sk: Bytes) {
        return KeyGenInternal(Dilithium.randomBytes(32))
    }
    
    // [FIPS 204] - Algorithm 2
    func Sign(_ sk: Bytes, _ M: Bytes, _ ctx: Bytes, _ randomize: Bool, _ aHat: Matrix) -> Bytes {
        assert(sk.count == 128 + 32 * ((self.l + self.k) * Dilithium.bitlen(self.eta << 1) + self.k * Dilithium.D))
        assert(ctx.count < 256)
        let M1: Bytes = [0] + [Byte(ctx.count)] + ctx + M
        return SignInternal(sk, M1, randomize ? Dilithium.randomBytes(32) : Bytes(repeating: 0, count: 32), aHat)
    }

    // [FIPS 204] - Algorithm 3
    func Verify(_ pk: Bytes, _ M: Bytes, _ sigma: Bytes, _ ctx: Bytes, _ aHat: Matrix) -> Bool {
        assert(pk.count == 32 + 32 * self.k * (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D))
        assert(ctx.count < 256)
        let M1: Bytes = [0] + [Byte(ctx.count)] + ctx + M
        return VerifyInternal(pk, M1, sigma, aHat)
    }

    // [FIPS 204] - Algorithm 4
    func hashSign(_ sk: Bytes, _ M: Bytes, _ ctx: Bytes, _ PH: PreHash, _ randomize: Bool, _ aHat: Matrix) -> Bytes {
        assert(sk.count == 128 + 32 * ((self.l + self.k) * Dilithium.bitlen(self.eta << 1) + self.k * Dilithium.D))
        assert(ctx.count < 256)
        var OID: Bytes
        var phM: Bytes
        switch PH {
        case .SHA2_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4]
            phM = MessageDigest(.SHA2_224).digest(M)
        case .SHA2_256, .SHA256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1]
            phM = MessageDigest(.SHA2_256).digest(M)
        case .SHA2_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2]
            phM = MessageDigest(.SHA2_384).digest(M)
        case .SHA2_512, .SHA512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3]
            phM = MessageDigest(.SHA2_512).digest(M)
        case .SHA2_512_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 5]
            phM = MessageDigest(.SHA2_512_224).digest(M)
        case .SHA2_512_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 6]
            phM = MessageDigest(.SHA2_512_256).digest(M)
        case .SHA3_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 7]
            phM = MessageDigest(.SHA3_224).digest(M)
        case .SHA3_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 8]
            phM = MessageDigest(.SHA3_256).digest(M)
        case .SHA3_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 9]
            phM = MessageDigest(.SHA3_384).digest(M)
        case .SHA3_512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10]
            phM = MessageDigest(.SHA3_512).digest(M)
        case .SHAKE128:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 11]
            phM = XOF(.XOF128, M).read(32)
        case .SHAKE256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 12]
            phM = XOF(.XOF256, M).read(64)
        }
        let M1: Bytes = [1] + [Byte(ctx.count)] + ctx + OID + phM
        return SignInternal(sk, M1, randomize ? Dilithium.randomBytes(32) : Bytes(repeating: 0, count: 32), aHat)
    }

    // [FIPS 204] - Algorithm 5
    func hashVerify(_ pk: Bytes, _ M: Bytes, _ sigma: Bytes, _ ctx: Bytes, _ PH: PreHash, _ aHat: Matrix) -> Bool {
        assert(pk.count == 32 + 32 * self.k * (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D))
        assert(ctx.count < 256)
        var OID: Bytes
        var phM: Bytes
        switch PH {
        case .SHA2_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4]
            phM = MessageDigest(.SHA2_224).digest(M)
        case .SHA2_256, .SHA256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1]
            phM = MessageDigest(.SHA2_256).digest(M)
        case .SHA2_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2]
            phM = MessageDigest(.SHA2_384).digest(M)
        case .SHA2_512, .SHA512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3]
            phM = MessageDigest(.SHA2_512).digest(M)
        case .SHA2_512_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 5]
            phM = MessageDigest(.SHA2_512_224).digest(M)
        case .SHA2_512_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 6]
            phM = MessageDigest(.SHA2_512_256).digest(M)
        case .SHA3_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 7]
            phM = MessageDigest(.SHA3_224).digest(M)
        case .SHA3_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 8]
            phM = MessageDigest(.SHA3_256).digest(M)
        case .SHA3_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 9]
            phM = MessageDigest(.SHA3_384).digest(M)
        case .SHA3_512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10]
            phM = MessageDigest(.SHA3_512).digest(M)
        case .SHAKE128:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 11]
            phM = XOF(.XOF128, M).read(32)
        case .SHAKE256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 12]
            phM = XOF(.XOF256, M).read(64)
        }
        let M1: Bytes = [1] + [Byte(ctx.count)] + ctx + OID + phM
        return VerifyInternal(pk, M1, sigma, aHat)
    }

    // [FIPS 204] - Algorithm 6
    func KeyGenInternal(_ xi: Bytes) -> (pk: Bytes, sk: Bytes) {
        assert(xi.count == 32)
        let H = XOF(.XOF256, xi + [Byte(self.k)] + [Byte(self.l)])
        let rho = H.read(32)
        let rho1 = H.read(64)
        let K = H.read(32)
        let aHat = ExpandA(rho)
        let (s1, s2) = ExpandS(rho1)
        let t = (aHat * s1.NTT()).INTT() + s2        
        let (t1, t0) = Dilithium.Power2Round(t)
        let pk = pkEncode(rho, t1)
        let tr = XOF(.XOF256, pk).read(64)
        let sk = skEncode(rho, K, tr, s1, s2, t0)
        return (pk, sk)
    }

    // [FIPS 204] - Algorithm 7
    func SignInternal(_ sk: Bytes, _ M: Bytes, _ rnd: Bytes, _ aHat: Matrix) -> Bytes {
        assert(sk.count == 128 + 32 * ((self.l + self.k) * Dilithium.bitlen(self.eta << 1) + self.k * Dilithium.D))
        let (_, K, tr, s1, s2, t0) = skDecode(sk)
        let s1Hat = s1.NTT()
        let s2Hat = s2.NTT()
        let t0Hat = t0.NTT()
        let my = XOF(.XOF256, tr + M).read(64)
        let rho1 = XOF(.XOF256, K + rnd + my).read(64)
        var kappa = 0
        var z = Vector(self.l)
        var h = Vector(self.k)
        var cTilde: Bytes = []
        var zhBlank = true
        while zhBlank {
            let y = ExpandMask(rho1, kappa)
            let w = (aHat * y.NTT()).INTT()
            let w1 = HighBits(w)
            cTilde = XOF(.XOF256, my + w1Encode(w1)).read(self.lambda >> 2)
            let c = SampleInBall(cTilde)
            let cHat = c.NTT()
            let cs1 = (cHat * s1Hat).INTT()
            let cs2 = (cHat * s2Hat).INTT()
            z = y + cs1
            let r0 = LowBits(w - cs2)
            if z.checkNorm(self.gamma1 - self.beta) || r0.checkNorm(self.gamma2 - self.beta) {
                zhBlank = true
            } else {
                let ct0 = (cHat * t0Hat).INTT()
                h = MakeHint(-ct0, w - cs2 + ct0)
                if ct0.checkNorm(self.gamma2) || h.OneCount() > self.omega {
                    zhBlank = true
                } else {
                    zhBlank = false
                }
            }
            kappa += self.l
        }
        return sigEncode(cTilde, z.modPMQ(), h)
    }

    // [FIPS 204] - Algorithm 8
    func VerifyInternal(_ pk: Bytes, _ M: Bytes, _ sigma: Bytes, _ aHat: Matrix) -> Bool {
        assert(pk.count == 32 + 32 * self.k * (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D))
        assert(sigma.count == self.lambda >> 2 + 32 * self.l * (1 + Dilithium.bitlen(self.gamma1 - 1)) + self.omega + self.k)
        let (_, t1) = pkDecode(pk)
        let (cTilde, z, _h) = sigDecode(sigma)
        guard let h = _h else {
            return false
        }
        let tr = XOF(.XOF256, pk).read(64)
        let my = XOF(.XOF256, tr + M).read(64)
        let c = SampleInBall(cTilde)
        let wApprox = (aHat * z.NTT() - c.NTT() * (t1 * (1 << Dilithium.D)).NTT()).INTT()
        let w1 = UseHint(h, wApprox)
        let cTilde1 = XOF(.XOF256, my + w1Encode(w1)).read(self.lambda >> 2)
        return !z.checkNorm(self.gamma1 - self.beta) && cTilde == cTilde1
    }

    // [FIPS 204] - Algorithm 14
    static func CoeffFromThreeBytes(_ b: Bytes) -> Int {
        assert(b.count == 3)
        let b0 = Int(b[0])
        let b1 = Int(b[1])
        let b2 = Int((b[2] << 1) >> 1)
        let z = b2 << 16 + b1 << 8 + b0
        return z < Dilithium.Q ? z : BLANK
    }
    
    // [FIPS 204] - Algorithm 15
    func CoeffFromHalfByte(_ b: Byte) -> Int {
        assert(0 <= b && b < 16)
        let b_ = Int(b)
        if self.eta == 2 && b < 15 {
            return 2 - b_ % 5
        } else if self.eta == 4 && b < 9 {
            return 4 - b_
        } else {
            return Dilithium.BLANK
        }
    }
    
    // [FIPS 204] - Algorithm 16
    static func SimpleBitPack(_ w: Polynomial, _ b: Int) -> Bytes {
        assert(b > 0)
        var z = Bytes(repeating: 0, count: Dilithium.bitlen(b) << 5)
        var zi = 0
        var bitNo = 0
        let bl = Dilithium.bitlen(b)
        let mask = bl == 63 ? 0x7fffffffffffffff : 1 << bl - 1
        for i in 0 ..< 256 {
            assert(0 <= w.coef[i] && w.coef[i] <= b)
            var x = w.coef[i] & mask
            var remaining = bl
            while remaining > 0 {
                z[zi] |= Byte(x & 0xff) << bitNo
                if remaining + bitNo < 8 {
                    bitNo += remaining
                    remaining = 0
                } else if remaining + bitNo > 8 {
                    x >>= (8 - bitNo)
                    remaining -= (8 - bitNo)
                    bitNo = 0
                    zi += 1
                } else {
                    remaining = 0
                    bitNo = 0
                    zi += 1
                }
            }
        }
        return z
    }

    // [FIPS 204] - Algorithm 17
    static func BitPack(_ w: Polynomial, _ a: Int, _ b: Int) -> Bytes {
        assert(a > 0)
        assert(b > 0)
        let bl = Dilithium.bitlen(a + b)
        let mask = 1 << bl - 1
        var z = Bytes(repeating: 0, count: bl << 5)
        var zi = 0
        var bitNo = 0
        for i in 0 ..< 256 {
            assert(-a <= w.coef[i] && w.coef[i] <= b)
            var x = (b - w.coef[i]) & mask
            var remaining = bl
            while remaining > 0 {
                z[zi] |= Byte(x & 0xff) << bitNo
                if remaining + bitNo < 8 {
                    bitNo += remaining
                    remaining = 0
                } else if remaining + bitNo > 8 {
                    x >>= (8 - bitNo)
                    remaining -= (8 - bitNo)
                    bitNo = 0
                    zi += 1
                } else {
                    remaining = 0
                    bitNo = 0
                    zi += 1
                }
            }
        }
        return z
    }

    // [FIPS 204] - Algorithm 18
    static func SimpleBitUnpack(_ ny: Bytes, _ b: Int) -> Polynomial {
        assert(ny.count == Dilithium.bitlen(b) * 32)
        assert(b > 0)
        let c = Dilithium.bitlen(b)
        var w = [Int](repeating: 0, count: 256)
        var nyi = 0
        var bitNo = 0
        for i in 0 ..< 256 {
            var x = 0
            for j in 0 ..< c {
                if bitNo == 8 {
                    bitNo = 0
                    nyi += 1
                }
                let bit = Int(ny[nyi] >> bitNo) & 1
                x |= bit << j
                bitNo += 1
            }
            w[i] = x
            assert(0 <= w[i] && w[i] <= (c == 63 ? 0x7fffffffffffffff : 1 << c - 1))
        }
        return Polynomial(w)
    }

    // [FIPS 204] - Algorithm 19
    static func BitUnpack(_ ny: Bytes, _ a: Int, _ b: Int) -> Polynomial {
        assert(ny.count == 32 * Dilithium.bitlen(a + b))
        assert(a > 0)
        assert(b > 0)
        let c = Dilithium.bitlen(a + b)
        var w = [Int](repeating: 0, count: 256)
        var nyi = 0
        var bitNo = 0
        for i in 0 ..< 256 {
            var x = 0
            for j in 0 ..< c {
                if bitNo == 8 {
                    bitNo = 0
                    nyi += 1
                }
                let bit = Int(ny[nyi] >> bitNo) & 1
                x |= bit << j
                bitNo += 1
            }
            w[i] = b - x
            assert((b - (1 << c) + 1) <= w[i] && w[i] <= b)
        }
        return Polynomial(w)
    }

    // [FIPS 204] - Algorithm 20
    func HintBitPack(_ h: Vector) -> Bytes {
        assert(h.n == self.k)
        var y = Bytes(repeating: 0, count: self.k + self.omega)
        var index = 0
        for i in 0 ..< self.k {
            for j in 0 ..< 256 {
                if h.polynomial[i].coef[j] != 0 {
                    y[index] = Byte(j)
                    index += 1
                }
            }
            y[self.omega + i] = Byte(index)
        }
        return y
    }

    // [FIPS 204] - Algorithm 21
    func HintBitUnpack(_ y: Bytes) -> Vector? {
        assert(y.count == self.omega + self.k)
        var h = Vector(self.k)
        var index = 0
        for i in 0 ..< self.k {
            if y[self.omega + i] < index || y[self.omega + i] > self.omega {
                return nil
            }
            let first = index
            while index < y[self.omega + i] {
                if index > first && y[index - 1] >= y[index] {
                    return nil
                }
                h.polynomial[i].coef[Int(y[index])] = 1
                index += 1
            }
        }
        for i in index ..< self.omega {
            if y[i] != 0 {
                return nil
            }
        }
        return h
    }
    
    // [FIPS 204] - Algorithm 22
    func pkEncode(_ rho: Bytes, _ t1: Vector) -> Bytes {
        assert(rho.count == 32)
        assert(t1.n == self.k)
        var pk = rho
        for i in 0 ..< self.k {
            pk += Dilithium.SimpleBitPack(t1.polynomial[i], 1 << (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D) - 1)
        }
        return pk
    }

    // [FIPS 204] - Algorithm 23
    func pkDecode(_ pk: Bytes) -> (rho: Bytes, t1: Vector) {
        assert(pk.count == 32 + 32 * self.k * (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D))
        var pkSlice = pk.sliced()
        let rho = pkSlice.next(32)
        var t1 = Vector(self.k)
        let l = (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D) << 5
        for i in 0 ..< self.k {
            t1.polynomial[i] = Dilithium.SimpleBitUnpack(pkSlice.next(l), 1 << (Dilithium.bitlen(Dilithium.Q - 1) - Dilithium.D) - 1)
        }
        return (rho, t1)
    }
    
    // [FIPS 204] - Algorithm 24
    func skEncode(_ rho: Bytes, _ K: Bytes, _ tr: Bytes, _ s1: Vector, _ s2: Vector, _ t0: Vector) -> Bytes {
        assert(rho.count == 32)
        assert(K.count == 32)
        assert(tr.count == 64)
        assert(s1.n == self.l)
        assert(s2.n == self.k)
        let bitPackLength = 1 << (Dilithium.D - 1)
        var sk = rho + K + tr
        for i in 0 ..< self.l {
            sk += Dilithium.BitPack(s1.polynomial[i], self.eta, self.eta)
        }
        for i in 0 ..< self.k {
            sk += Dilithium.BitPack(s2.polynomial[i], self.eta, self.eta)
        }
        for i in 0 ..< self.k {
            sk += Dilithium.BitPack(t0.polynomial[i], bitPackLength - 1, bitPackLength)
        }
        return sk
    }

    // [FIPS 204] - Algorithm 25
    func skDecode(_ sk: Bytes) -> (rho: Bytes, K: Bytes, tr: Bytes, s1: Vector, s2: Vector, t0: Vector) {
        assert(sk.count == 128 + 32 * ((self.l + self.k) * Dilithium.bitlen(2 * self.eta) + self.k * Dilithium.D))
        let bitPackLength = 1 << (Dilithium.D - 1)
        var skSlice = sk.sliced()
        let rho = skSlice.next(32)
        let K = skSlice.next(32)
        let tr = skSlice.next(64)
        let l1 = (Dilithium.bitlen(2 * self.eta)) << 5
        var s1 = Vector(self.l)
        for i in 0 ..< self.l {
            s1.polynomial[i] = Dilithium.BitUnpack(skSlice.next(l1), self.eta, self.eta)
        }
        var s2 = Vector(self.k)
        for i in 0 ..< self.k {
            s2.polynomial[i] = Dilithium.BitUnpack(skSlice.next(l1), self.eta, self.eta)
        }
        let l2 = Dilithium.D << 5
        var t0 = Vector(self.k)
        for i in 0 ..< self.k {
            t0.polynomial[i] = Dilithium.BitUnpack(skSlice.next(l2), bitPackLength - 1, bitPackLength)
        }
        return (rho, K, tr, s1, s2, t0)
    }

    // [FIPS 204] - Algorithm 26
    func sigEncode(_ cTilde: Bytes, _ z: Vector, _ h: Vector) -> Bytes {
        assert(cTilde.count == self.lambda / 4)
        assert(z.n == self.l)
        assert(h.n == self.k)
        var sigma = cTilde
        for i in 0 ..< self.l {
            sigma += Dilithium.BitPack(z.polynomial[i], self.gamma1 - 1, self.gamma1)
        }
        sigma += HintBitPack(h)
        return sigma
    }

    // [FIPS 204] - Algorithm 27
    func sigDecode(_ sigma: Bytes) -> (c: Bytes, z: Vector, h: Vector?) {
        assert(sigma.count == self.lambda / 4 + 32 * self.l * (1 + Dilithium.bitlen(self.gamma1 - 1)) + self.omega + self.k)
        var sigmaSlice = sigma.sliced()
        let cTilde = sigmaSlice.next(self.lambda >> 2)
        var z = Vector(self.l)
        let l = (1 + Dilithium.bitlen(self.gamma1 - 1)) << 5
        for i in 0 ..< self.l {
            z.polynomial[i] = Dilithium.BitUnpack(sigmaSlice.next(l), self.gamma1 - 1, self.gamma1)
        }
        let h = HintBitUnpack(sigmaSlice.next(self.omega + self.k))
        return (cTilde, z, h)
    }

    // [FIPS 204] - Algorithm 28
    func w1Encode(_  w1: Vector) -> Bytes {
        assert(w1.n == self.k)
        var w1Hat: Bytes = []
        let l = (Dilithium.Q - 1) / (self.gamma2 << 1) - 1
        for i in 0 ..< self.k {
            w1Hat += Dilithium.SimpleBitPack(w1.polynomial[i], l)
        }
        return w1Hat
    }

    // [FIPS 204] - Algorithm 29
    func SampleInBall(_ rho: Bytes) -> Polynomial {
        assert(rho.count == self.lambda / 4)
        let xof = XOF(.XOF256, rho)
        let signs = xof.read(8)
        var sign = UInt(0)
        for i in 0 ..< 8 {
            sign |= (UInt(signs[i]) << (i * 8))
        }
        var c = [Int](repeating: 0, count: 256)
        for i in 256 - self.tau ..< 256 {
            var j = 0
            while true {
                let x = xof.read(1)
                if x[0] <= i {
                    j = Int(x[0])
                    break
                }
            }
            c[i] = c[j]
            c[j] = sign & 1 == 1 ? -1 : 1
            sign >>= 1
        }
        return Polynomial(c)
    }
    
    // [FIPS 204] - Algorithm 30
    static func RejNTTPoly(_ rho: Bytes) -> Polynomial {
        assert(rho.count == 34)
        var aHat = Polynomial()
        let xof = XOF(.XOF128, rho)
        var j = 0
        while j < 256 {
            aHat.coef[j] = Dilithium.CoeffFromThreeBytes(xof.read(3))
            if aHat.coef[j] != Dilithium.BLANK {
                j += 1
            }
        }
        return aHat
    }

    // [FIPS 204] - Algorithm 31
    func RejBoundedPoly(_ rho: Bytes) -> Polynomial {
        assert(rho.count == 66)
        var a = [Int](repeating: 0, count: 256)
        let xof = XOF(.XOF256, rho)
        var j = 0
        while j < 256 {
            let z = xof.read(1)
            let z0 = CoeffFromHalfByte(z[0] & 0xf)
            let z1 = CoeffFromHalfByte(z[0] >> 4)
            if z0 != Dilithium.BLANK {
                a[j] = z0
                j += 1
            }
            if z1 != Dilithium.BLANK && j < 256 {
                a[j] = z1
                j += 1
            }
        }
        return Polynomial(a)
    }
    
    // [FIPS 204] - Algorithm 32
    func ExpandA(_ rho: Bytes) -> Matrix {
        assert(rho.count == 32)
        var A = Matrix(self.k, self.l)
        for r in 0 ..< self.k {
            for s in 0 ..< self.l {
                let rho1 = rho + [Byte(s)] + [Byte(r)]
                A.vector[r].polynomial[s] = Dilithium.RejNTTPoly(rho1)
            }
        }
        return A
    }

    // [FIPS 204] - Algorithm 33
    func ExpandS(_ rho: Bytes) -> (s1: Vector, s2: Vector) {
        assert(rho.count == 64)
        var s1 = Vector(self.l)
        for r in 0 ..< self.l {
            s1.polynomial[r] = RejBoundedPoly(rho + [Byte(r), 0])
        }
        var s2 = Vector(self.k)
        for r in 0 ..< self.k {
            s2.polynomial[r] = RejBoundedPoly(rho + [Byte(r + self.l), 0])
        }
        return (s1, s2)
    }
    
    // [FIPS 204] - Algorithm 34
    func ExpandMask(_ rho: Bytes, _ my: Int) -> Vector {
        assert(rho.count == 64)
        assert(my >= 0)
        var y = Vector(self.l)
        let c = 1 + Dilithium.bitlen(self.gamma1 - 1)
        for r in 0 ..< self.l {
            let v = XOF(.XOF256, rho + [Byte((my + r) & 0xff)] + [Byte((my + r) >> 8)]).read(c << 5)
            y.polynomial[r] = Dilithium.BitUnpack(v, self.gamma1 - 1, self.gamma1)
        }
        return y
    }

    // [FIPS 204] - Algorithm 35
    static func Power2Round(_ r: Int) -> (r1: Int, r0: Int) {
        let rp = Dilithium.modQ(r)
        let r0 = Dilithium.modPM(rp, 1 << Dilithium.D)
        return ((rp - r0) >> Dilithium.D, r0)
    }
    
    // Polynomial version
    static func Power2Round(_ r: Polynomial) -> (p1: Polynomial, p0: Polynomial) {
        var p1 = Polynomial()
        var p0 = Polynomial()
        for i in 0 ..< 256 {
            (p1.coef[i], p0.coef[i]) = Dilithium.Power2Round(r.coef[i])
        }
        return (p1, p0)
    }

    static func Power2Round(_ r: Vector) -> (v1: Vector, v0: Vector) {
        var v1 = Vector(r.n)
        var v0 = Vector(r.n)
        for i in 0 ..< r.n {
            (v1.polynomial[i], v0.polynomial[i]) = Dilithium.Power2Round(r.polynomial[i])
        }
        return (v1, v0)
    }

    // [FIPS 204] - Algorithm 36
    func Decompose(_ r: Int) -> (r1: Int, r0: Int) {
        let rp = Dilithium.modQ(r)
        var r0 = Dilithium.modPM(rp, self.gamma2 << 1)
        var r1: Int
        if rp - r0 == Dilithium.Q - 1 {
            r1 = 0
            r0 -= 1
        } else {
            r1 = (rp - r0) / (self.gamma2 << 1)
        }
        return (r1, r0)
    }
    
    // [FIPS 204] - Algorithm 37
    func HighBits(_ r: Int) -> Int {
        return Decompose(r).r1
    }
    
    // Polynomial version
    func HighBits(_ r: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = HighBits(r.coef[i])
        }
        return Polynomial(x)
    }

    // Vector version
    func HighBits(_ r: Vector) -> Vector {
        var x = Vector(r.n)
        for i in 0 ..< x.n {
            x.polynomial[i] = HighBits(r.polynomial[i])
        }
        return x
    }

    // [FIPS 204] - Algorithm 38
    func LowBits(_ r: Int) -> Int {
        return Decompose(r).r0
    }
    
    // Polynomial version
    func LowBits(_ r: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = LowBits(r.coef[i])
        }
        return Polynomial(x)
    }

    // Vector version
    func LowBits(_ r: Vector) -> Vector {
        var x = Vector(r.n)
        for i in 0 ..< x.n {
            x.polynomial[i] = LowBits(r.polynomial[i])
        }
        return x
    }

    // [FIPS 204] - Algorithm 39
    func MakeHint(_ z: Int, _ r: Int) -> Int {
        return HighBits(r) != HighBits(r + z) ? 1 : 0
    }

    // Polynomial version
    func MakeHint(_ h: Polynomial, _ r: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = MakeHint(h.coef[i], r.coef[i])
        }
        return Polynomial(x)
    }
    
    // Vector version
    func MakeHint(_ h: Vector, _ r: Vector) -> Vector {
        var x = Vector(r.n)
        for i in 0 ..< r.n {
            x.polynomial[i] = MakeHint(h.polynomial[i], r.polynomial[i])
        }
        return x
    }

    // [FIPS 204] - Algorithm 40
    func UseHint(_ h: Int, _ r: Int) -> Int {
        assert(h == 0 || h == 1)
        let m = (Dilithium.Q - 1) / (self.gamma2 << 1)
        let (r1, r0) = Decompose(r)
        if h == 1 && r0 > 0 {
            return Dilithium.mod(r1 + 1, m)
        } else if h == 1 && r0 <= 0 {
            return Dilithium.mod(r1 - 1, m)
        } else {
            return r1
        }
    }

    // Polynomial version
    func UseHint(_ h: Polynomial, _ r: Polynomial) -> Polynomial {
        var x = [Int](repeating: 0, count: 256)
        for i in 0 ..< 256 {
            x[i] = UseHint(h.coef[i], r.coef[i])
        }
        return Polynomial(x)
    }

    // Vector version
    func UseHint(_ h: Vector, _ r: Vector) -> Vector {
        var x = Vector(r.n)
        for i in 0 ..< r.n {
            x.polynomial[i] = UseHint(h.polynomial[i], r.polynomial[i])
        }
        return x
    }

}
