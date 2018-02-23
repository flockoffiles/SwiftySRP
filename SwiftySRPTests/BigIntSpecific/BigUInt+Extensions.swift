//
//  BigUInt+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey Novitsky on 27/11/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import SwiftySRP
import BigInt
import FFDataWrapper

/// Custom extension to make third party BigUInt type conform to SRPBigIntProtocol
extension BigUInt: SRPBigIntProtocol
{
    public init(_ other: BigUInt)
    {
        self = other
    }
    
    /// Initialize with an unsigned value stored in a big endian data buffer.
    ///
    /// - Parameter data: Wrapped data buffer holding the value.
    public init(_ wrappedData: FFDataWrapper)
    {
        // Do NOT copy the data given to the closure, so that it can be wiped properly.
        self = wrappedData.withDecodedData { BigUInt($0) }
    }
    
    /// Store the data in a wrapped big endian data buffer (more secure)
    ///
    /// - Returns: The big endian data buffer which contains the value.
    public func wrappedSerialize() -> FFDataWrapper
    {
        var serialized = serialize()
        defer { FFDataWrapper.wipe(&serialized) }
        return FFDataWrapper(serialized)
    }
}

/// Helper extension to provide a simple method for conversion to hex string.
public extension BigUInt
{
    /// Convert to hex string. Uses a String initializer from BigUInt
    ///
    /// - Returns: Hex string representation (uppercase, without 0x) of the current BigUInt
    func hexString() -> String
    {
        return String(self, radix: 16, uppercase: true)
    }
}

/// Helper category to output hex string representation to the debug console.
extension BigUInt: CustomDebugStringConvertible
{
    public var debugDescription: String {
        return String(self, radix: 16, uppercase: true)
    }
}
