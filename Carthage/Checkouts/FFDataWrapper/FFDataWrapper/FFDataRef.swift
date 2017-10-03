//
//  FFDataRef.swift
//  FFDataWrapper
//
//  Created by Sergey Novitsky on 26/09/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

/// Helper class which makes sure that the internal representation gets wiped securely when FFDataWrapper is destroyed.
internal class FFDataRef
{
    /// Pointer to the data buffer holding the internal representation of the wrapper data.
    var dataBuffer: UnsafeMutablePointer<UInt8>
    /// Length of the dataBuffer in bytes.
    var length: Int
    
    /// Create a buffer holder with the given initialized buffer.
    ///
    /// - Parameters:
    ///   - dataBuffer: The relevant data buffer.
    ///   - length: Actual buffer length.
    init(dataBuffer: UnsafeMutablePointer<UInt8>, length: Int)
    {
        self.dataBuffer = dataBuffer
        self.length = length
    }
    
    deinit
    {
        // Explicitly clear the buffer (important)!
        dataBuffer.initialize(to: 0, count: length)
        dataBuffer.deallocate(capacity: length)
    }
}

extension FFDataRef: CustomStringConvertible
{
    static func hexString(_ dataBuffer: UnsafePointer<UInt8>, _ length: Int) -> String
    {
        var result = String()
        result.reserveCapacity(length * 2)
        for i in 0 ..< length
        {
            result += String(format: "%02X", dataBuffer[i])
        }
        return result
    }

    public var description: String {
        let content = type(of: self).hexString(dataBuffer, length)
        return "FFDataRef: \(content)"
    }
}

