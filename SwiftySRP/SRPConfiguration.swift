//
//  SRPConfiguration.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

public typealias DigestFunc = (Data) -> Data
public typealias HMacFunc = (Data, Data) -> Data


/// Configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
public protocol SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var modulus: Data { get }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var generator: Data { get }
    
    /// Hash function to be used.
    var digest: DigestFunc { get }
    
    /// Function to calculate HMAC
    var hmac: HMacFunc { get }
    
    /// Function to calculate parameter a (per SRP spec above)
    func a() -> Data
    
    /// Function to calculate parameter b (per SRP spec above)
    func b() -> Data
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
}
