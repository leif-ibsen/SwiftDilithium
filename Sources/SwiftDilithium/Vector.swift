//
//  Vector.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 16/11/2023.
//

struct Vector: Equatable {
        
    var polynomial: [Polynomial]
    let n: Int

    init(_ n: Int) {
        self.polynomial = [Polynomial](repeating: Polynomial(), count: n)
        self.n = n
    }

    // Number Theoretic Transform
    func NTT() -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v[i] = self[i].NTT()
        }
        return v
    }

    // Inverse Number Theoretic Transform
    func INTT() -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v[i] = self[i].INTT()
        }
        return v
    }

    func modPMQ() -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v[i] = self[i].modPMQ()
        }
        return v
    }

    func OneCount() -> Int {
        var x = 0
        for i in 0 ..< self.n {
            x += self[i].OneCount()
        }
        return x
    }

    func checkNorm(_ limit: Int) -> Bool {
        for i in 0 ..< self.n {
            if self[i].checkNorm(limit) {
                return true
            }
        }
        return false
    }

    // v1 + v2
    static func +(_ v1: Vector, _ v2: Vector) -> Vector {
        assert(v1.n == v2.n)
        var sum = Vector(v1.n)
        for i in 0 ..< sum.n {
            sum[i] = v1[i] + v2[i]
        }
        return sum
    }

    // -v
    static prefix func -(v: Vector) -> Vector {
        var x = Vector(v.n)
        for i in 0 ..< v.n {
            x[i] = -v[i]
        }
        return x
    }

    // v1 - v2
    static func -(_ v1: Vector, _ v2: Vector) -> Vector {
        assert(v1.n == v2.n)
        var diff = Vector(v1.n)
        for i in 0 ..< diff.n {
            diff[i] = v1[i] - v2[i]
        }
        return diff
    }

    // p * v
    static func *(_ p: Polynomial, _ v: Vector) -> Vector {
        var x = Vector(v.n)
        for i in 0 ..< x.n {
            x[i] = p * v[i]
        }
        return x
    }

    // v * d
    static func *(_ v: Vector, _ d: Int) -> Vector {
        var x = Vector(v.n)
        for i in 0 ..< x.n {
            x[i] = v[i] * d
        }
        return x
    }

}

extension Vector {
    
    subscript(i: Int) -> Polynomial {
        get {
            return self.polynomial[i]
        }
        set {
            self.polynomial[i] = newValue
        }
    }
}
