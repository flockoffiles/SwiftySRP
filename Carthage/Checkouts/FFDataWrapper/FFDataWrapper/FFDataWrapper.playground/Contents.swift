//: Playground - noun: a place where people can play

import UIKit
@testable import FFDataWrapper

extension Data
{
    /// Convert data to a hex string
    ///
    /// - Returns: hex string representation of the data.
    func hexString() -> String
    {
        var result = String()
        result.reserveCapacity(self.count * 2)
        [UInt8](self).forEach { (aByte) in
            result += String(format: "%02X", aByte)
        }
        return result
    }

}

func address(_ o: UnsafeRawPointer) -> UnsafeRawPointer
{
    return o
}

var s1: String = "ABCD"
let s1StringCorePtr = address(&s1)
let s1BaseAddress = s1StringCorePtr.assumingMemoryBound(to: UnsafeRawPointer.self).pointee
var s2 = s1

s1.wipe()

let copiedString = String(cString: s1BaseAddress.assumingMemoryBound(to: CChar.self), encoding: .utf8)

//
let s1StringCorePtr2 = address(&s1)
let s1BaseAddress2 = s1StringCorePtr2.assumingMemoryBound(to: UnsafeRawPointer.self).pointee
let copiedString2 = String(cString: s1BaseAddress2.assumingMemoryBound(to: CChar.self), encoding: .utf8)

let s2StringCorePtr = address(&s2)
let s2BaseAddress = s2StringCorePtr.assumingMemoryBound(to: UnsafeRawPointer.self).pointee
let copiedString22 = String(cString: s2BaseAddress.assumingMemoryBound(to: CChar.self), encoding: .utf8)

//let s1StringCorePtr2 = s1Address2.assumingMemoryBound(to: UnsafeRawPointer.self).pointee
//let s1BaseAddress2 = s1StringCorePtr2.assumingMemoryBound(to: UnsafeRawPointer.self).pointee








