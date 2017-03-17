//
//  SRP.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 09/02/2017.
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
import BigInt

/// This class serves as a namespace for SRP related methods. It is not meant to be instantiated.
/// For a short description of the SRP protocol, see SRPProtocol.swift
public class SRP
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
    public static func configuration(N: Data,
                              g: Data,
                              digest: @escaping DigestFunc = SRP.sha256DigestFunc,
                              hmac: @escaping HMacFunc = SRP.sha256HMacFunc) throws -> SRPConfiguration
    {
        let result = SRPConfigurationBigIntImpl(N: BigUInt(N),
                                          g: BigUInt(g),
                                          digest: digest,
                                          hmac: hmac,
                                          aFunc: nil,
                                          bFunc: nil)
        try result.validate()
        return result
    }
    
    
    /// Create an instance of SRPProtocol with the given configuration.
    ///
    /// - Parameter configuration: SRP configuration to use.
    /// - Returns: The resulting SRP protocol implementation.
    public static func srpProtocol(_ configuration: SRPConfiguration) -> SRPProtocol
    {
        return SRPBigIntImpl(configuration: configuration)
    }
    
    /// SHA256 hash function
    public static let sha256DigestFunc: DigestFunc = CryptoAlgorithm.SHA256.digestFunc()
    
    /// SHA512 hash function
    public static let sha512DigestFunc: DigestFunc = CryptoAlgorithm.SHA512.digestFunc()
    
    /// SHA256 hash function
    public static let sha256HMacFunc: HMacFunc = CryptoAlgorithm.SHA256.hmacFunc()
    
    /// SHA512 hash function
    public static let sha512HMacFunc: HMacFunc = CryptoAlgorithm.SHA512.hmacFunc()
    
}



