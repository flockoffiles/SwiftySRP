//
//  SRPMpzT.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

import Foundation
import FFDataWrapper
import SwiftySRP.Private

/// This class wraps an mpz_t value from imath and provides methods to conform to SRPBigIntProtocol
public final class SRPMpzT: SRPBigIntProtocol
{
    /// Wrapped value
    fileprivate var value = mpz_t()
    
    /// Default initializer
    public required init()
    {
        mp_int_init(&value)
    }
    
    
    /// Initialize with an Int value
    ///
    /// - Parameter intValue: The Int value to initialize with.
    public required init(_ intValue: Int)
    {
        mp_int_init_value(&value, intValue)
    }
    
    
    /// Initialize with an unsigned value stored in a big endian data buffer.
    ///
    /// - Parameter data: Data buffer holding the value.
    public required init(_ data: Data)
    {
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Void in
            mp_int_read_const_unsigned(&value, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
    }
    
    /// Initialize with an unsigned value stored in a big endian data buffer.
    ///
    /// - Parameter data: Wrapped data buffer holding the value.
    public required init(_ wrappedData: FFDataWrapper)
    {
        wrappedData.mapData { decodedData in
            decodedData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Void in
                mp_int_read_const_unsigned(&value, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(decodedData.count))
            }
        }
    }
    
    /// Initialize with another wrapped value.
    ///
    /// - Parameter other: The wrapped value to initialize with.
    public required init(_ other: SRPMpzT)
    {
        mp_int_init_const_copy(&value, &other.value)
    }

    /// Custom deinit - clears the wrapped value.
    deinit
    {
        mp_int_clear(&value)
    }
    
    
    /// Store the data in a big endian data buffer
    ///
    /// - Returns: The big endian data buffer which contains the value.
    public func serialize() -> Data
    {
        let byteCount = mp_int_unsigned_len(&value)
        guard byteCount != mp_result(0) else {
            return Data()
        }
        
        var data = Data(count: Int(byteCount))
        data.withUnsafeMutableBytes({ (bytes: UnsafeMutableRawBufferPointer) -> Void in
            mp_int_to_unsigned(&value, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), byteCount)
        })
        
        return data
    }
    
    /// Store the data in a wrapped big endian data buffer (more secure)
    ///
    /// - Returns: The big endian data buffer which contains the value.
    public func wrappedSerialize() -> FFDataWrapper
    {
        let byteCount = mp_int_unsigned_len(&value)
        guard byteCount != mp_result(0) else {
            return FFDataWrapper()
        }
        
        var data = Data(count: Int(byteCount))
        defer { FFDataWrapper.wipe(&data) }
        data.withUnsafeMutableBytes({ (bytes: UnsafeMutableRawBufferPointer) -> Void in
            mp_int_to_unsigned(&value, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), byteCount)
        })

        return FFDataWrapper(data: data)
    }
    
    /// Number of bits needed to represent the value.
    public var bitWidth: Int {
        return Int(mp_int_count_bits(&self.value))
    }

    
    /// Compute the remainder of division of x by y
    ///
    /// - Parameters:
    ///   - x: Dividend
    ///   - y: Divisor
    /// - Returns: The remainder of an integer division of the dividend by the divisor
    public static func %(x: SRPMpzT, y: SRPMpzT) -> SRPMpzT
    {
        // c = a % m
        let result = SRPMpzT()
        mp_int_mod(&x.value, &y.value, &result.value)
        return result
    }
    
    /// Compute the result of multiplication of x by y
    ///
    /// - Parameters:
    ///   - x: multiplicand
    ///   - y: Multiplier
    /// - Returns: The result of multiplication
    public static func *(x: SRPMpzT, y: SRPMpzT) -> SRPMpzT
    {
        // c = a * b
        let result = SRPMpzT()
        mp_int_mul(&x.value, &y.value, &result.value)
        return result
    }
    
    
    /// Compute the result of addition of a and b
    ///
    /// - Parameters:
    ///   - a: First additive
    ///   - b: Second additive
    /// - Returns: The result of addition a + b
    public static func +(a: SRPMpzT, b: SRPMpzT) -> SRPMpzT
    {
        // c = a + b
        let result = SRPMpzT()
        mp_int_add(&a.value, &b.value, &result.value)
        return result
    }

    
    /// Compute the result of subtraction a - b
    ///
    /// - Parameters:
    ///   - a: The number to subtract from (minuend)
    ///   - b: The number being subtracted (subtrahend)
    /// - Returns: Difference
    public static func -(a: SRPMpzT, b: SRPMpzT) -> SRPMpzT
    {
        let result = SRPMpzT()
        mp_int_sub(&a.value, &b.value, &result.value)
        return result
    }
    
    
    /// Compute the result of modular exponentiation of the current value by the exponent; with the given modulus.
    ///
    /// - Parameters:
    ///   - exponent: The exponent
    ///   - modulus: The modulus to be used.
    /// - Returns: Result of modular exponentiation of the current value by the exponent; with the given modulus.
    public func power(_ exponent: SRPMpzT, modulus: SRPMpzT) -> SRPMpzT
    {
        // mp_result mp_int_exptmod(mp_int a, mp_int b, mp_int m, mp_int c);
        /* c = a^b (mod m) */
        let result = SRPMpzT()
        mp_int_exptmod(&value, &exponent.value, &modulus.value, &result.value)
        return result
    }
    
    
    /// Compute the result of exponentiation of the current value to the given integer exponent.
    ///
    /// - Parameter exponent: The pertaining integer exponent.
    /// - Returns: Result of exponentiation of the current value to the given integer exponent.
    public func power(_ exponent: Int) -> SRPMpzT
    {
        let result = SRPMpzT()
        mp_int_expt(&value, exponent, &result.value)
        return result
    }

    
    /// Generate a random integer which can be represented by the given maximum number of bits
    ///
    /// - Parameter width: The desired maximum number of bits to represent the integer.
    /// - Returns: Random integer.
    static func randomInteger(withMaximumWidth width: Int) -> SRPMpzT
    {
        guard width > 0 else { return SRPMpzT(0) }
        
        let byteCount = (width + 7) / 8
        assert(byteCount > 0)
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: byteCount)
        arc4random_buf(buffer, byteCount)
        if width % 8 != 0 {
            buffer[0] &= UInt8(1 << (width % 8) - 1)
        }
        defer {
            buffer.deinitialize(count: byteCount)
            buffer.deallocate()
        }
        return SRPMpzT(Data(bytesNoCopy: buffer, count: byteCount, deallocator: .none))
    }

    
    /// Generate a positive random integer which is less than the specified integer.
    ///
    /// - Parameter limit: The upper bound (non inclusive) for the desired random integer.
    /// - Returns: positive random integer which is less than the specified upper bound.
    public static func randomInteger(lessThan limit: SRPMpzT) -> SRPMpzT
    {
        let width = limit.bitWidth
        var random = randomInteger(withMaximumWidth: width)
        while random >= limit
        {
            random = randomInteger(withMaximumWidth: width)
        }
        return random
    }
}

/// Custom extension implementing Comparable protocol.
extension SRPMpzT: Comparable
{
    
    /// Compare two wrapped values.
    ///
    /// - Parameters:
    ///   - a: First value
    ///   - b: Second value
    /// - Returns: .orderedAscending if a < b; .orderedDescending if a > b; .orderedSame if a == b
    static func compare(_ a: SRPMpzT, _ b: SRPMpzT) -> ComparisonResult
    {
        let result = mp_int_compare(&a.value, &b.value)
        if result < 0 { return .orderedAscending }
        else if result > 0 { return .orderedDescending }
        return .orderedSame
    }
    
    
    /// Compare two wrapped values for equality.
    ///
    /// - Parameters:
    ///   - a: First value
    ///   - b: Second value
    /// - Returns: true if values are equal; false otherwise.
    public static func ==(a: SRPMpzT, b: SRPMpzT) -> Bool
    {
        return SRPMpzT.compare(a, b) == .orderedSame
    }
    
    
    /// Check if value a is less than the given other value b
    ///
    /// - Parameters:
    ///   - a: The value to check
    ///   - b: The value to check against.
    /// - Returns: true if a < b; false otherwise.
    public static func <(a: SRPMpzT, b: SRPMpzT) -> Bool {
        return SRPMpzT.compare(a, b) == .orderedAscending
    }
    
    
    /// Check if the wrapped value is zero.
    public var isZero: Bool
    {
        return mp_int_compare_zero(&value) == 0
    }
}
