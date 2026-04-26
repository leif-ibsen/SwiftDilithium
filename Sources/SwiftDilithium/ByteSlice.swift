//
//  ByteSlice.swift
//  Slice
//
//  Created by Leif Ibsen on 09/12/2023.
//

struct ByteSlice {
    
    let slice: ArraySlice<Byte>
    var from: Int
    
    init(_ array: Bytes) {
        self.slice = array[0 ..< array.count]
        self.from = 0
    }
    
    mutating func next(_ n: Int) -> Bytes {
        self.from += n
        return Bytes(self.slice[self.from - n ..< self.from])
    }
    
}

extension Array where Element == Byte {
    
    func sliced() -> ByteSlice {
        return ByteSlice(self)
    }
    
}
