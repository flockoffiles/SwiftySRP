//
//  SRPUtil.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt
import CommonCrypto

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
                    CCHmac(CCHmacAlgorithm(self.hmacAlgorithm), keyBytes, key.count, dataBytes, data.count, &result)
                }
            }
            
            return Data(result)
        }
    }
}


/// Helper category to perform conversion of hex strings to data
extension UnicodeScalar
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


/// Helper category to perform conversion of hex strings to data
extension Data
{
    
    /// Create an instance of Data from a hex string representation.
    ///
    /// - Parameter hex: hex string from which to create the data
    init(hex:String)
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
        self = Data(bytes: bytes)
    }
    
    
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


