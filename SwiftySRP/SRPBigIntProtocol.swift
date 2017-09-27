//
//  SRPBigIntProtocol.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
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

/// Protocol definition for big integer types used in SRP implementation.
public protocol SRPBigIntProtocol: Comparable
{
    /// Default initializer
    init()
    
    /// Initialize with an Int value
    ///
    /// - Parameter intValue: The Int value to initialize with.
    init(_ intValue: Int)
    
    /// Initialize with an unsigned value stored in a big endian data buffer.
    ///
    /// - Parameter data: Data buffer holding the value.
    init(_ data: Data)
    
    /// Initialize with another wrapped value.
    ///
    /// - Parameter other: The wrapped value to initialize with.
    init(_ other: Self)
    
    /// Initialize with an unsigned value stored in a big endian data buffer.
    ///
    /// - Parameter data: Wrapped data buffer holding the value.
    init(_ wrappedData: FFDataWrapper)
    
    /// Store the data in a big endian data buffer
    ///
    /// - Returns: The big endian data buffer which contains the value.
    func serialize() -> Data
    
    /// Store the data in a wrapped big endian data buffer (more secure)
    ///
    /// - Returns: The big endian data buffer which contains the value.
    func wrappedSerialize() -> FFDataWrapper
    
    /// Number of bits needed to represent the value.
    var bitWidth: Int { get }
    
    /// Compute the remainder of division of x by y
    ///
    /// - Parameters:
    ///   - x: Dividend
    ///   - y: Divisor
    /// - Returns: The remainder of an integer division of the dividend by the divisor
    static func %(x: Self, y: Self) -> Self
    
    /// Compute the result of multiplication of x by y
    ///
    /// - Parameters:
    ///   - x: multiplicand
    ///   - y: Multiplier
    /// - Returns: The result of multiplication
    static func *(x: Self, y: Self) -> Self
    
    /// Compute the result of addition of a and b
    ///
    /// - Parameters:
    ///   - a: First additive
    ///   - b: Second additive
    /// - Returns: The result of addition a + b
    static func +(a: Self, b: Self) -> Self
    
    /// Compute the result of subtraction a - b
    ///
    /// - Parameters:
    ///   - a: The number to subtract from (minuend)
    ///   - b: The number being subtracted (subtrahend)
    /// - Returns: Difference
    static func -(a: Self, b: Self) -> Self
    
    /// Compute the result of modular exponentiation of the current value by the exponent; with the given modulus.
    ///
    /// - Parameters:
    ///   - exponent: The exponent
    ///   - modulus: The modulus to be used.
    /// - Returns: Result of modular exponentiation of the current value by the exponent; with the given modulus.
    func power(_ exponent: Self, modulus: Self) -> Self
    
    /// Compute the result of exponentiation of the current value to the given integer exponent.
    ///
    /// - Parameter exponent: The pertaining integer exponent.
    /// - Returns: Result of exponentiation of the current value to the given integer exponent.
    func power(_ exponent: Int) -> Self
    
    /// Generate a random integer which can be represented by the given maximum number of bits
    ///
    /// - Parameter width: The desired maximum number of bits to represent the integer.
    /// - Returns: Random integer.
    static func randomInteger(lessThan limit: Self) -> Self
}
