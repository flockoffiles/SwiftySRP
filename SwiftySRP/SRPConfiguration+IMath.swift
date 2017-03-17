//
//  SRPConfiguration+IMath.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

// Internal extension to short-circuit conversions between Data and SRPMpzT
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var mpz_N: SRPMpzT {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationIMathImpl
            {
                return impl._N
            }
            return SRPMpzT(modulus)
        }
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var mpz_g: SRPMpzT {
        get {
            // Shortcut to avoid converting to Data and back.
            if let impl = self as? SRPConfigurationIMathImpl
            {
                return impl._g
            }
            return SRPMpzT(generator)
        }
    }
    
    /// Client private value
    func mpz_a() -> SRPMpzT
    {
        if let impl = self as? SRPConfigurationIMathImpl
        {
            return impl._a()
        }
        return SRPMpzT(clientPrivateValue())
    }
    
    /// Server private value
    func mpz_b() -> SRPMpzT
    {
        if let impl = self as? SRPConfigurationIMathImpl
        {
            return impl._b()
        }
        return SRPMpzT(serverPrivateValue())
    }
}

