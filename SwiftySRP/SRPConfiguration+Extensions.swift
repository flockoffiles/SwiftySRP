//
//  SRPConfiguration+Extensions.swift
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

// Internal extension to short-circuit conversions between Data and BigIntType
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    func bigInt_N<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Shortcut to avoid converting to Data and back.
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._N
        }
        return BigIntType(modulus)
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    func bigInt_g<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Shortcut to avoid converting to Data and back.
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._g
        }
        return BigIntType(generator)
    }
    
    /// Client private value
    func bigInt_a<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._a()
        }
        return BigIntType(clientPrivateValue())
    }
    
    /// Server private value
    func bigInt_b<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._b()
        }
        return BigIntType(serverPrivateValue())
    }
}

