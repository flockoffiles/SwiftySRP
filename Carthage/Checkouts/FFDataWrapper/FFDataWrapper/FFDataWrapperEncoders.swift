//
//  FFDataWrapperEncoders.swift
//  FFDataWrapper
//
//  Created by Sergey Novitsky on 26/09/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

/// Enumeration defining some basic coders (transformers)
public enum FFDataWrapperEncoders
{
    /// Do not transform. Just copy.
    case identity
    /// XOR with the random vector of the given legth.
    case xorWithRandomVectorOfLength(Int)
    
    var coders: (encoder: FFDataWrapperCoder, decoder: FFDataWrapperCoder) {
        switch self
        {
        case .identity:
            return (encoder: FFDataWrapperEncoders.identityFunction(), FFDataWrapperEncoders.identityFunction())
        case .xorWithRandomVectorOfLength(let length):
            var vector = Data(count: length)
            let _ = vector.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, length, $0)
            }
            
            return (encoder: FFDataWrapperEncoders.xorWithVector(vector), decoder: FFDataWrapperEncoders.xorWithVector(vector))
        }
    }
    
    internal static func xorWithVector(_ vector: Data) -> FFDataWrapperCoder
    {
        return { (src: UnsafePointer<UInt8>, srcLength: Int, dest: UnsafeMutablePointer<UInt8>, destLength: Int) in
            xor(src: src, srcLength: srcLength, dest: dest, destLength: destLength, with: vector)
        }
    }
    
    internal static func identityFunction() -> FFDataWrapperCoder
    {
        return { (src: UnsafePointer<UInt8>, srcLength: Int, dest: UnsafeMutablePointer<UInt8>, destLength: Int) in
            justCopy(src: src, srcLength: srcLength, dest: dest, destLength: destLength)
        }
    }
}

extension FFDataWrapperEncoders
{
    /// Simple identity transformation.
    ///
    /// - Parameters:
    ///   - src: Source data to transform.
    ///   - srcLength: Length of the source data.
    ///   - dest: Destination data buffer. Will be cleared before transformation takes place.
    internal static func justCopy(src: UnsafePointer<UInt8>, srcLength: Int, dest: UnsafeMutablePointer<UInt8>, destLength: Int)
    {
        // Wipe contents if needed.
        if (destLength > 0)
        {
            dest.initialize(to: 0, count: destLength)
        }
        
        guard srcLength > 0 && destLength >= srcLength else {
            return
        }
        
        dest.assign(from: src, count: srcLength)
    }
    

    
    /// Sample transformation for custom content. XORs the source representation (byte by byte) with the given vector.
    ///
    /// - Parameters:
    ///   - src: Source data to transform.
    ///   - srcLength: Length of the source data.
    ///   - dest: Destination data buffer. Will be cleared before transformation takes place.
    ///   - with: Vector to XOR with. If the vector is shorter than the original data, it will be wrapped around.
    internal static func xor(src: UnsafePointer<UInt8>, srcLength: Int, dest: UnsafeMutablePointer<UInt8>, destLength: Int, with: Data)
    {
        // Initialize contents
        if (destLength > 0)
        {
            dest.initialize(to: 0, count: destLength)
        }
        
        guard srcLength > 0 && destLength >= srcLength else {
            return
        }
        
        var j = 0
        for i in 0 ..< srcLength
        {
            dest[i] = src[i] ^ with[j]
            j += 1
            if j >= with.count
            {
                j = 0
            }
        }
    }
}
