//
//  SRPConfiguration+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

// Internal extension to short-circuit conversions between Data and BigIntType
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    func N<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Shortcut to avoid converting to Data and back.
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._N
        }
        return BigIntType(modulus)
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    func g<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Shortcut to avoid converting to Data and back.
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._g
        }
        return BigIntType(generator)
    }
    
    /// Client private value
    func a<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._a()
        }
        return BigIntType(clientPrivateValue())
    }
    
    /// Server private value
    func b<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        if let impl = self as? SRPConfigurationGenericImpl<BigIntType>
        {
            return impl._b()
        }
        return BigIntType(serverPrivateValue())
    }
}

