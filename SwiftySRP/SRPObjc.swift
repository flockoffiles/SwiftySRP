//
//  SRPObjc.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 20/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

/// Configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
@objc public protocol SRPConfigurationObject: NSObjectProtocol
{
    /// A large safe prime per SRP spec.
    var N: Data { get }
    
    /// A generator modulo N
    var g: Data { get }
    
    /// Hash function to be used.
    var digest: DigestFunc { get }
    
    /// Function to calculate HMAC
    var hmac: HMacFunc { get }
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be non-zero.
    /// - Throws: SRPError if invalid.
    func validate() throws
}

class SRPConfigurationObjectImpl: NSObject, SRPConfigurationObject
{
    let configuration: SRPConfiguration
    
    required init(configuration: SRPConfiguration)
    {
        self.configuration = configuration
        super.init()
    }

    /// A large safe prime per SRP spec.
    public var N: Data {
        return configuration.N.serialize()
    }

    /// A generator modulo N
    public var g: Data {
        return configuration.g.serialize()
    }
    
    /// Hash function to be used.
    public var digest: DigestFunc {
        return configuration.digest
    }
    
    /// Function to calculate HMAC
    public var hmac: HMacFunc {
        return configuration.hmac
    }
    
    /// Function to calculate parameter a (per SRP spec above)
    public var a: PrivateValueFunc {
        return configuration.a
    }

    /// Function to calculate parameter b (per SRP spec above)
    public var b: PrivateValueFunc {
        return configuration.b
    }

    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be non-zero.
    /// - Throws: SRPError if invalid.
    public func validate() throws {
        try configuration.validate()
    }
}


@objc public class SRPObjC: NSObject
{
    /// Create an SRP configuration with the given parameters.
    ///
    /// - Parameters:
    ///   - N: Safe large prime per SRP spec. You can generate the prime with openssl: openssl dhparam -text 2048
    ///   - g: Group generator per SRP spec.
    ///   - digest: Hash function to be used.
    ///   - hmac: HMAC function to be used.
    /// - Throws: SRPError if configuration parameters are not valid.
    /// - Returns: The resulting SRP configuration.
    @objc(configurationWithN:g:digest:hmac:error:)
    public static func configuration(N: Data,
                              g: Data,
                              digest: @escaping DigestFunc,
                              hmac: @escaping HMacFunc) throws -> SRPConfigurationObject
    {
        let result = SRPConfigurationImpl(N: BigUInt(N),
                                          g: BigUInt(g),
                                          digest: digest,
                                          hmac: hmac,
                                          a: SRPConfigurationImpl.generatePrivateValue,
                                          b: SRPConfigurationImpl.generatePrivateValue)
        try result.validate()
        return SRPConfigurationObjectImpl(configuration:result)
    }

}

