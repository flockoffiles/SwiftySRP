//
//  SRPConfiguration.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
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

/// Digest (hash) function to use in SRP (used in calculations and to derive a single shared key from the shared secret).
public typealias DigestFunc = (Data) -> Data

/// HMAC function to use in SRP (used to derive multiple keys from the same shared secret).
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
    func clientPrivateValue() -> Data
    
    /// Function to calculate parameter a (per SRP spec above). Returns a wrapped value (more secure).
    func wrappedClientPrivateValue() -> FFDataWrapper
    
    /// Function to calculate parameter b (per SRP spec above)
    func serverPrivateValue() -> Data
    
    /// Function to calculate parameter b (per SRP spec above). Returns a wrapped value (more secure).
    func wrappedServerPrivateValue() -> FFDataWrapper
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
}
