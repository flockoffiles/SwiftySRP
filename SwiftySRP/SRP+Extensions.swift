//
//  SRP+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

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
    /// - Returns: The resulting SRP protocol implementation.
    public func `protocol`(N: Data,
                           g: Data,
                           digest: @escaping DigestFunc = SRP.sha256DigestFunc,
                           hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
                           a: @escaping () -> Data,
                           b: @escaping () -> Data) throws -> SRPProtocol
    {
        switch self
        {
        case .bigUInt:
            let configuration = SRPConfigurationGenericImpl<BigUInt>(N: BigUInt(N),
                                                                     g: BigUInt(g),
                                                                     digest: digest,
                                                                     hmac: hmac,
                                                                     aFunc: { _ in return BigUInt(a()) },
                                                                     bFunc: { _ in return BigUInt(b()) })
            return SRPBigIntImpl(configuration: configuration)
        case .iMath:
            let configuration = SRPConfigurationGenericImpl<SRPMpzT>(N: SRPMpzT(N),
                                                                     g: SRPMpzT(g),
                                                                     digest: digest,
                                                                     hmac: hmac,
                                                                     aFunc: { _ in return SRPMpzT(a()) },
                                                                     bFunc: { _ in return SRPMpzT(b()) })
            return SRPIMathImpl(configuration: configuration)
        }
    }
}

