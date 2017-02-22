//
//  SRP+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

typealias PrivateValueFunc = () -> BigUInt

/// Internal extension. For test purposes only.
/// Allows to create a configuration with custom (fixed) private ephemeral values 'a' and 'b'
extension SRP
{
    /// Only for use in testing! Create an SRP configuration and provide custom closures to generate private ephemeral values 'a' and 'b'
    /// This is done to be able to use fixed values for 'a' and 'b' and make generated values predictable (and compare them with expected values).
    /// - Parameters:
    ///   - N: Safe large prime per SRP spec.
    ///   - g: Group generator per SRP spec.
    ///   - digest: Hash function to be used.
    ///   - hmac: HMAC function to be used.
    ///   - a: Custom closure to generate the private ephemeral value 'a'
    ///   - b: Custom closure to generate the private ephemeral value 'b'
    /// - Throws: SRPError if configuration parameters are not valid.
    /// - Returns: The resulting SRP configuration.
    static func configuration(N: Data,
                              g: Data,
                              digest: @escaping DigestFunc = SRP.sha256DigestFunc,
                              hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
                              a: @escaping PrivateValueFunc,
                              b: @escaping PrivateValueFunc) throws -> SRPConfiguration
    {
        let result = SRPConfigurationImpl(N: BigUInt(N),
                                          g: BigUInt(g),
                                          digest: digest,
                                          hmac: hmac,
                                          aFunc: a,
                                          bFunc: b)
        try result.validate()
        return result
    }
}

