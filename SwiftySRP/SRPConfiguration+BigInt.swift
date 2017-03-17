//
//  SRPConfiguration+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

// Internal extension to short-circuit conversions between Data and BigUInt
// in case the default implementation struct (SRPConfigurationBigIntImpl) is used
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var uint_N: BigUInt {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationBigIntImpl
            {
                return impl._N
            }
            return BigUInt(modulus)
        }
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var uint_g: BigUInt {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationBigIntImpl
            {
                return impl._g
            }
            return BigUInt(generator)
        }
    }
    
    /// Client private value
    func uint_a() -> BigUInt
    {
        if let impl = self as? SRPConfigurationBigIntImpl
        {
            return impl._a()
        }
        return BigUInt(clientPrivateValue())
    }
    
    /// Server private value
    func uint_b() -> BigUInt
    {
        if let impl = self as? SRPConfigurationBigIntImpl
        {
            return impl._b()
        }
        return BigUInt(serverPrivateValue())
    }
}

