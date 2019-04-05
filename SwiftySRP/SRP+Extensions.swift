//
//  SRP+Extensions.swift
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


/// Internal extension. For test purposes only.
/// Allows to create a configuration with custom (fixed) private ephemeral values 'a' and 'b'
public extension SRP
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
    static func `protocol`<BigIntType: SRPBigIntProtocol>(N: BigIntType,
                                                          g: BigIntType,
                                                     digest: @escaping DigestFunc = CryptoAlgorithm.SHA256.digestFunc(),
                                                       hmac: @escaping HMacFunc = CryptoAlgorithm.SHA256.hmacFunc(),
                                                          a: @escaping () -> Data,
                                                          b: @escaping () -> Data) throws -> SRPProtocol
    {
        let configuration = SRPConfigurationGenericImpl<BigIntType>(N: N,
                                                                    g: g,
                                                                    digest: digest,
                                                                    hmac: hmac,
                                                                    aFunc: { BigIntType(a()) },
                                                                    bFunc: { BigIntType(b()) })
        return SRPGenericImpl<BigIntType>(configuration: configuration)

    }
}

