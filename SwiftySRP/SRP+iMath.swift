//
//  SRP+iMath.swift
//  SwiftySRP
//
//  Created by Sergey Novitsky on 27/11/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

public extension SRP
{
    static var iMath: SRPIMathFactory {
        return SRPIMathFactory()
    }
}

public struct SRPIMathFactory
{
    /// Create an instance of SRPProtocol with the given configuration.
    /// - Parameters:
    ///   - N: Safe large prime per SRP spec. You can generate the prime with openssl: openssl dhparam -text 2048
    ///   - g: Group generator per SRP spec.
    ///   - digest: Hash function to be used.
    ///   - hmac: HMAC function to be used.
    /// - Throws: SRPError if configuration parameters are not valid.
    /// - Returns: The resulting SRP protocol implementation.
    public func `protocol`(N: Data,
                           g: Data,
                           digest: @escaping DigestFunc = CryptoAlgorithm.SHA256.digestFunc(),
                           hmac: @escaping HMacFunc = CryptoAlgorithm.SHA256.hmacFunc()) throws -> SRPProtocol
    {
        let configuration = SRPConfigurationGenericImpl<SRPMpzT>(N: SRPMpzT(N),
                                                                 g: SRPMpzT(g),
                                                                 digest: digest,
                                                                 hmac: hmac,
                                                                 aFunc: nil,
                                                                 bFunc: nil)
        try configuration.validate()
        return SRPGenericImpl<SRPMpzT>(configuration: configuration)
    }
    
}

