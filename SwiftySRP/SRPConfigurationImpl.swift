//
//  SRPConfigurationImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

// Internal extension to short-circuit conversions between Data and BigUInt
// in case the default implementation struct (SRPConfigurationImpl) is used
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var N: BigUInt {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationImpl
            {
                return impl.uint_N
            }
            return BigUInt(modulus)
        }
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var g: BigUInt {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationImpl
            {
                return impl.uint_g
            }
            return BigUInt(generator)
        }
    }
    
    /// Client private value
    func a() -> BigUInt
    {
        if let impl = self as? SRPConfigurationImpl
        {
            return impl.uint_a()
        }
        return BigUInt(clientPrivateValue())
    }
    
    /// Server private value
    func b() -> BigUInt
    {
        if let impl = self as? SRPConfigurationImpl
        {
            return impl.uint_b()
        }
        return BigUInt(serverPrivateValue())
    }
}


/// Implementation: configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
struct SRPConfigurationImpl: SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var modulus: Data {
        return uint_N.serialize()
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var generator: Data {
        return uint_g.serialize()
    }
    
    /// A large safe prime per SRP spec.
    let uint_N: BigUInt
    
    /// A generator modulo N
    let uint_g: BigUInt
    
    /// Hash function to be used.
    let digest: DigestFunc
    
    /// Function to calculate HMAC
    let hmac: HMacFunc
    
    /// Custom function to generate 'a'
    let aFunc: PrivateValueFunc?
    
    /// Custom function to generate 'b'
    let bFunc: PrivateValueFunc?
    
    
    /// Create a configuration with the given parameters.
    ///
    /// - Parameters:
    ///   - N: The modulus (large safe prime) (per SRP spec.)
    ///   - g: The group generator (per SRP spec.)
    ///   - digest: Hash function to be used in intermediate calculations and to derive a single shared key from the shared secret.
    ///   - hmac: HMAC function to be used when deriving multiple shared keys from a single shared secret.
    ///   - aFunc: (ONLY for testing purposes) Custom function to generate the client private value.
    ///   - bFunc: (ONLY for testing purposes) Custom function to generate the server private value.
    init(N: BigUInt,
         g: BigUInt,
         digest: @escaping DigestFunc = SRP.sha256DigestFunc,
         hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
         aFunc: PrivateValueFunc?,
         bFunc: PrivateValueFunc?)
    {
        self.uint_N = N
        self.uint_g = g
        self.digest = digest
        self.hmac = hmac
        self.aFunc = aFunc
        self.bFunc = bFunc
    }
    
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
    {
        guard N.width >= 256 else { throw SRPError.configurationPrimeTooShort }
        guard g > 1 else { throw SRPError.configurationGeneratorInvalid }
    }
    
    /// Generate a random private value less than the given value N and at least half the bit size of N
    ///
    /// - Parameter N: The value determining the range of the random value to generate.
    /// - Returns: Randomly generate value.
    public static func generatePrivateValue(N: BigUInt) -> BigUInt
    {
        // Suppose that N is 8 bits wide
        // Then min bits == 4
        let minBits = N.width / 2
        // Smallest number with 4 bits is 2^(4-1) = 8
        let minBitsNumber = BigUInt(2).power(minBits > 0 ? minBits - 1: 0)
        let random = minBitsNumber + BigUInt.randomIntegerLessThan(N - minBitsNumber)
        
        return random
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func uint_a() -> BigUInt
    {
        if let aFunc = self.aFunc
        {
            return aFunc()
        }
        return SRPConfigurationImpl.generatePrivateValue(N: uint_N)
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func clientPrivateValue() -> Data
    {
        return uint_a().serialize()
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func uint_b() -> BigUInt
    {
        if let bFunc = self.bFunc
        {
            return bFunc()
        }
        return SRPConfigurationImpl.generatePrivateValue(N: uint_N)
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func serverPrivateValue() -> Data
    {
        return uint_b().serialize()
    }
}



