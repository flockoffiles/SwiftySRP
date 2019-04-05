//
//  SRP+iMath+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey Novitsky on 27/11/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

public extension SRPIMathFactory
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
    func `protocol`(N: Data,
                    g: Data,
                    digest: @escaping DigestFunc = CryptoAlgorithm.SHA256.digestFunc(),
                    hmac: @escaping HMacFunc = CryptoAlgorithm.SHA256.hmacFunc(),
                    a: @escaping () -> Data,
                    b: @escaping () -> Data) throws -> SRPProtocol
    {
        let configuration = SRPConfigurationGenericImpl<SRPMpzT>(N: SRPMpzT(N),
                                                                 g: SRPMpzT(g),
                                                                 digest: digest,
                                                                 hmac: hmac,
                                                                 aFunc: { SRPMpzT(a()) },
                                                                 bFunc: { SRPMpzT(b()) })
        return SRPGenericImpl<SRPMpzT>(configuration: configuration)
    }

}
