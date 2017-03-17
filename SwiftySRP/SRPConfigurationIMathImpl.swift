//
//  SRPConfigurationIMathImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

/// Implementation: configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
struct SRPConfigurationIMathImpl: SRPConfiguration
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
    let _N: SRPMpzT
    
    /// A generator modulo N
    let _g: SRPMpzT
    
    /// Hash function to be used.
    let digest: DigestFunc
    
    /// Function to calculate HMAC
    let hmac: HMacFunc
    
    /// Custom function to generate 'a'
    let _aFunc: PrivateValueIMathFunc?
    
    /// Custom function to generate 'b'
    let _bFunc: PrivateValueIMathFunc?
    
    
    /// Create a configuration with the given parameters.
    ///
    /// - Parameters:
    ///   - N: The modulus (large safe prime) (per SRP spec.)
    ///   - g: The group generator (per SRP spec.)
    ///   - digest: Hash function to be used in intermediate calculations and to derive a single shared key from the shared secret.
    ///   - hmac: HMAC function to be used when deriving multiple shared keys from a single shared secret.
    ///   - aFunc: (ONLY for testing purposes) Custom function to generate the client private value.
    ///   - bFunc: (ONLY for testing purposes) Custom function to generate the server private value.
    init(N: SRPMpzT,
         g: SRPMpzT,
         digest: @escaping DigestFunc = SRP.sha256DigestFunc,
         hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
         aFunc: PrivateValueIMathFunc?,
         bFunc: PrivateValueIMathFunc?)
    {
        _N = SRPMpzT(N)
        _g = SRPMpzT(g)
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
        guard _N.width >= 256 else { throw SRPError.configurationPrimeTooShort }
        guard _g > SRPMpzT(1) else { throw SRPError.configurationGeneratorInvalid }
    }
    
    /// Generate a random private value less than the given value N and at least half the bit size of N
    ///
    /// - Parameter N: The value determining the range of the random value to generate.
    /// - Returns: Randomly generate value.
    public static func generatePrivateValue(N: SRPMpzT) -> SRPMpzT
    {
        // Suppose that N is 8 bits wide
        // Then min bits == 4
        let minBits = N.width / 2
        guard minBits > 0 else { return SRPMpzT.randomIntegerLessThan(SRPMpzT(2)) }
            
        // Smallest number with 4 bits is 2^(4-1) = 8
        let minBitsNumber = SRPMpzT(pow(2, minBits - 1))
        let random = minBitsNumber + SRPMpzT.randomIntegerLessThan(N - minBitsNumber)
        
        return random
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func mpz_a() -> SRPMpzT
    {
        if let aFunc = _aFunc
        {
            return aFunc()
        }
        return SRPConfigurationIMathImpl.generatePrivateValue(N: _N)
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    func clientPrivateValue() -> Data
    {
        return mpz_a().serialize()
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func mpz_b() -> SRPMpzT
    {
        if let bFunc = _bFunc
        {
            return bFunc()
        }
        return SRPConfigurationIMathImpl.generatePrivateValue(N: _N)
    }
    
    /// Function to calculate parameter b (per SRP spec above)
    func serverPrivateValue() -> Data
    {
        return mpz_b().serialize()
    }
}

