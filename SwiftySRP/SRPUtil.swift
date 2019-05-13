//
//  SRPUtil.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
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
import CommonCrypto
import FFDataWrapper

/// Convenience enum to specify a hashing algorithm
public enum CryptoAlgorithm
{
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    /// Returns the associated CCHmacAlgorithm
    var hmacAlgorithm: CCHmacAlgorithm
    {
        var result: Int = 0
        switch self
        {
        case .MD5:      result = kCCHmacAlgMD5
        case .SHA1:     result = kCCHmacAlgSHA1
        case .SHA224:   result = kCCHmacAlgSHA224
        case .SHA256:   result = kCCHmacAlgSHA256
        case .SHA384:   result = kCCHmacAlgSHA384
        case .SHA512:   result = kCCHmacAlgSHA512
        }
        
        return CCHmacAlgorithm(result)
    }
    
    /// Returns the associated digest length
    var digestLength: Int
    {
        var result: Int32 = 0
        switch self
        {
        case .MD5:      result = CC_MD5_DIGEST_LENGTH
        case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        
        return Int(result)
    }
    
    /// Returns the associated DigestFunc
    public func digestFunc()-> DigestFunc
    {
        return { (data: Data) in
            var hash = [UInt8](repeating: 0, count: self.digestLength)
            switch self
            {
            case .MD5:      CC_MD5(Array<UInt8>(data), CC_LONG(data.count), &hash)
            case .SHA1:     CC_SHA1(Array<UInt8>(data), CC_LONG(data.count), &hash)
            case .SHA224:   CC_SHA224(Array<UInt8>(data), CC_LONG(data.count), &hash)
            case .SHA256:   CC_SHA256(Array<UInt8>(data), CC_LONG(data.count), &hash)
            case .SHA384:   CC_SHA384(Array<UInt8>(data), CC_LONG(data.count), &hash)
            case .SHA512:   CC_SHA512(Array<UInt8>(data), CC_LONG(data.count), &hash)
            }
            return Data(hash)
        }
    }
    
    /// Returns the associated HMacFunc
    public func hmacFunc()-> HMacFunc
    {
        return { (key, data) in
            var result: [UInt8] = Array(repeating: 0, count: self.digestLength)
            
            key.withUnsafeBytes { keyBytes in
                data.withUnsafeBytes { dataBytes in
                    CCHmac(CCHmacAlgorithm(self.hmacAlgorithm), keyBytes.baseAddress!, key.count, dataBytes.baseAddress!, data.count, &result)
                }
            }
            
            return Data(result)
        }
    }
}


/// Helper category to perform conversion of hex strings to data
public extension UnicodeScalar
{
    var hexNibble:UInt8
    {
        let value = self.value
        if 48 <= value && value <= 57 {
            return UInt8(value - 48)
        }
        else if 65 <= value && value <= 70 {
            return UInt8(value - 55)
        }
        else if 97 <= value && value <= 102 {
            return UInt8(value - 87)
        }
        fatalError("\(self) not a legal hex nibble")

    }
}

/// Create an instance of Data from a hex string representation.
///
/// - Parameter hex: hex string from which to create the data
public func data(hex: String) -> Data
{
    let scalars = hex.unicodeScalars
    var bytes = Array<UInt8>(repeating: 0, count: (scalars.count + 1) >> 1)
    for (index, scalar) in scalars.enumerated()
    {
        var nibble = scalar.hexNibble
        if index & 1 == 0 {
            nibble <<= 4
        }
        bytes[index >> 1] |= nibble
    }
    return Data(bytes)
}

/// Convert data to a hex string
///
/// - Returns: hex string representation of the data.
public func hexString(data: Data) -> String
{
    var result = String()
    result.reserveCapacity(data.count * 2)
    [UInt8](data).forEach { (aByte) in
        result += String(format: "%02X", aByte)
    }
    return result
}

