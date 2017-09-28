//
//  SRPConfigurationGenericImpl.swift
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

/// Implementation: configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
struct SRPConfigurationGenericImpl<BigIntType: SRPBigIntProtocol>: SRPConfiguration
{
    typealias PrivateValueFunc = () -> BigIntType

    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var modulus: Data {
        return _N.serialize()
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var generator: Data {
        return _g.serialize()
    }
    
    /// A large safe prime per SRP spec.
    let _N: BigIntType
    
    /// A generator modulo N
    let _g: BigIntType
    
    /// Hash function to be used.
    let digest: DigestFunc
    
    /// Function to calculate HMAC
    let hmac: HMacFunc
    
    /// Custom function to generate 'a'
    let _aFunc: PrivateValueFunc?
    
    /// Custom function to generate 'b'
    let _bFunc: PrivateValueFunc?
    
    
    /// Create a configuration with the given parameters.
    ///
    /// - Parameters:
    ///   - N: The modulus (large safe prime) (per SRP spec.)
    ///   - g: The group generator (per SRP spec.)
    ///   - digest: Hash function to be used in intermediate calculations and to derive a single shared key from the shared secret.
    ///   - hmac: HMAC function to be used when deriving multiple shared keys from a single shared secret.
    ///   - aFunc: (ONLY for testing purposes) Custom function to generate the client private value.
    ///   - bFunc: (ONLY for testing purposes) Custom function to generate the server private value.
    init(N: BigIntType,
         g: BigIntType,
         digest: @escaping DigestFunc = CryptoAlgorithm.SHA256.digestFunc(),
         hmac: @escaping HMacFunc = CryptoAlgorithm.SHA256.hmacFunc(),
         aFunc: PrivateValueFunc?,
         bFunc: PrivateValueFunc?)
    {
        _N = BigIntType(N)
        _g = BigIntType(g)
        self.digest = digest
        self.hmac = hmac
        _aFunc = aFunc
        _bFunc = bFunc
    }
    
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
    {
        guard _N.bitWidth >= 256 else { throw SRPError.configurationPrimeTooShort }
        guard _g > BigIntType(1) else { throw SRPError.configurationGeneratorInvalid }
    }
    
    /// Generate a random private value less than the given value N and at least half the bit size of N
    ///
    /// - Parameter N: The value determining the range of the random value to generate.
    /// - Returns: Randomly generate value.
    public static func generatePrivateValue(N: BigIntType) -> BigIntType
    {
        // Suppose that N is 8 bits wide
        // Then min bits == 4
        let minBits = N.bitWidth / 2
        guard minBits > 0 else { return BigIntType.randomInteger(lessThan: BigIntType(2)) }
        
        // Smallest number with 4 bits is 2^(4-1) = 8
        let minBitsNumber = BigIntType(2).power(minBits - 1)
        let random = minBitsNumber + BigIntType.randomInteger(lessThan: N - minBitsNumber)
        
        return random
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func _a() -> BigIntType
    {
        if let aFunc = _aFunc
        {
            return aFunc()
        }
        return type(of: self).generatePrivateValue(N: _N)
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func clientPrivateValue() -> Data
    {
        return _a().serialize()
    }
    
    /// Function to calculate parameter a (per SRP spec above). Returns a wrapped value (more secure).
    func wrappedClientPrivateValue() -> FFDataWrapper
    {
        return _a().wrappedSerialize()
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func _b() -> BigIntType
    {
        if let bFunc = _bFunc
        {
            return bFunc()
        }
        return type(of: self).generatePrivateValue(N: _N)
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func serverPrivateValue() -> Data
    {
        return _b().serialize()
    }
    
    /// Function to calculate parameter b (per SRP spec above). Returns a wrapped value (more secure).
    func wrappedServerPrivateValue() -> FFDataWrapper
    {
        return _b().wrappedSerialize()
    }
}

