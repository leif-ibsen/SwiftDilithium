//
//  Matrix.swift
//  SwiftDilithium
//
//  Created by Leif Ibsen on 17/11/2023.
//

// Vector of vector of polynomials
struct Matrix: Equatable {
    
    var vector: [Vector]
    let r: Int
    let c: Int

    init(_ r: Int, _ c: Int) {
        self.vector = [Vector](repeating: Vector(c), count: r)
        self.r = r
        self.c = c
    }
    
    // m o v
    static func *(_ m: Matrix, _ v: Vector) -> Vector {
        assert(m.c == v.n)
        var x = Vector(m.r)
        for i in 0 ..< m.r {
            for j in 0 ..< m.c {
                x.polynomial[i] += m.vector[i].polynomial[j] * v.polynomial[j]
            }
        }
        return x
    }

}
