//
//  SRPMpzT.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import imath

final class SRPMpzT: SRPBigIntProtocol
{
    fileprivate var value = mpz_t()
    
    required init()
    {
        mp_int_init(&value)
    }
    
    required init(_ intValue: Int)
    {
        mp_int_init_value(&value, intValue)
    }
    
    required init(_ data: Data)
    {
        data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> Void in
            mp_int_read_const_unsigned(&value, bytes, Int32(data.count))
        }
    }
    
    required init(_ other: SRPMpzT)
    {
        mp_int_init_const_copy(&value, &other.value)
    }
    
    init(_ pValue: UnsafePointer<mpz_t>)
    {
        mp_int_init_const_copy(&self.value, pValue)
    }

    deinit
    {
        mp_int_clear(&value)
    }
    
    func serialize() -> Data
    {
        let byteCount = mp_int_unsigned_len(&value)
        if (byteCount == mp_result(0))
        {
            return Data()
        }
        
        var data = Data(count: Int(byteCount))
        data.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> Void in
            mp_int_to_unsigned(&value, bytes, byteCount)
        })
        
        return data
    }
    
    var width: Int {
        return Int(mp_int_count_bits(&self.value))
    }

    static func %(x: SRPMpzT, y: SRPMpzT) -> SRPMpzT
    {
        // c = a % m
        let result = SRPMpzT()
        mp_int_mod(&x.value, &y.value, &result.value)
        return result
    }
    
    static func *(x: SRPMpzT, y: SRPMpzT) -> SRPMpzT
    {
        // c = a * b
        let result = SRPMpzT()
        mp_int_mul(&x.value, &y.value, &result.value)
        return result
    }
    
    static func +(a: SRPMpzT, b: SRPMpzT) -> SRPMpzT
    {
        // c = a + b
        let result = SRPMpzT()
        mp_int_add(&a.value, &b.value, &result.value)
        return result
    }

    static func -(a: SRPMpzT, b: SRPMpzT) -> SRPMpzT
    {
        let result = SRPMpzT()
        mp_int_sub(&a.value, &b.value, &result.value)
        return result
    }
    
    func power(_ exponent: SRPMpzT, modulus: SRPMpzT) -> SRPMpzT
    {
        // mp_result mp_int_exptmod(mp_int a, mp_int b, mp_int m, mp_int c);
        /* c = a^b (mod m) */
        let result = SRPMpzT()
        mp_int_exptmod(&value, &exponent.value, &modulus.value, &result.value)
        return result
    }
    
    func power(_ exponent: Int) -> SRPMpzT
    {
        let result = SRPMpzT()
        mp_int_expt(&value, exponent, &result.value)
        return result
    }

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
            buffer.deallocate(capacity: byteCount)
        }
        return SRPMpzT(Data(bytesNoCopy: buffer, count: byteCount, deallocator: .none))
    }

    static func randomIntegerLessThan(_ limit: SRPMpzT) -> SRPMpzT
    {
        let width = limit.width
        var random = randomInteger(withMaximumWidth: width)
        while random >= limit
        {
            random = randomInteger(withMaximumWidth: width)
        }
        return random
    }
}

extension SRPMpzT: Comparable
{
    static func compare(_ a: SRPMpzT, _ b: SRPMpzT) -> ComparisonResult
    {
        let result = mp_int_compare(&a.value, &b.value)
        if result < 0 { return .orderedAscending }
        else if result > 0 { return .orderedDescending }
        return .orderedSame
    }
    
    static func ==(a: SRPMpzT, b: SRPMpzT) -> Bool
    {
        return SRPMpzT.compare(a, b) == .orderedSame
    }
    
    static func <(a: SRPMpzT, b: SRPMpzT) -> Bool {
        return SRPMpzT.compare(a, b) == .orderedAscending
    }
    
    var isZero: Bool
    {
        return mp_int_compare_zero(&value) == 0
    }
}
