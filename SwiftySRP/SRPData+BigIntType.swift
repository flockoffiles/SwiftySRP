//
//  SRPData+BigIntType.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 20/03/2017.
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

/// Internal extension to short-circuit conversions between Data and BigIntType
extension SRPData
{
    // Client specific data
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
    func bigInt_x<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._x
        }
        return BigIntType(passwordHash)
    }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    func bigInt_a<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._a
        }
        return BigIntType(clientPrivateValue)
    }
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    func bigInt_A<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._A
        }
        
        return BigIntType(clientPublicValue)
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    func bigInt_clientM<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._clientM
        }
        
        return BigIntType(clientEvidenceMessage)
    }
    
    mutating func setBigInt_clientM<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._clientM = newValue
            self = impl as! Self
        }
        else
        {
            clientEvidenceMessage = newValue.serialize()
        }

    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    func bigInt_serverM<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._serverM
        }
        return BigIntType(serverEvidenceMessage)
    }
    
    mutating func setBigInt_serverM<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._serverM = newValue
            self = impl as! Self
        }
        else
        {
            serverEvidenceMessage = newValue.serialize()
        }
    }
    
    // Common data:
    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    func bigInt_v<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._v
        }
        return BigIntType(verifier)

    }
    
    mutating func setBigInt_v<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._v = newValue
            self = impl as! Self
        }
        else
        {
            self.verifier = newValue.serialize()
        }
    }
    
    // Scrambler parameter 'u'. u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    func bigInt_u<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._u
        }
        return BigIntType(scrambler)
    }
    
    mutating func setBigInt_u<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._u = newValue
            self = impl as! Self
        }
        else
        {
            self.scrambler = newValue.serialize()
        }
    }
    
    /// Shared secret 'S' . Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    func bigInt_clientS<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._clientS
        }
        return BigIntType(clientSecret)
    }
    
    mutating func setBigInt_clientS<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._clientS = newValue
            self = impl as! Self
        }
        else
        {
            self.clientSecret = newValue.serialize()
        }
    }
    
    /// Shared secret 'S'. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    func bigInt_serverS<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._serverS
        }
        return BigIntType(serverSecret)
    }
    
    mutating func setBigInt_serverS<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._serverS = newValue
            self = impl as! Self
        }
        else
        {
            self.serverSecret = newValue.serialize()
        }
    }
    
    
    // Server specific data
    
    /// Multiplier parameter 'k'. Computed as: k = H(N, g) (see SRP spec. in SRPProtocol.swift)
    func bigInt_k<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._k
        }
        return BigIntType(multiplier)
    }
    
    mutating func setBigInt_k<BigIntType: SRPBigIntProtocol>(_ newValue: BigIntType)
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if var impl = self as? SRPDataGenericImpl<BigIntType>
        {
            impl._k = newValue
            self = impl as! Self
        }
        else
        {
            self.multiplier = newValue.serialize()
        }
    }
    
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    func bigInt_b<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._b
        }
        return BigIntType(serverPrivateValue)
    }
    
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    func bigInt_B<BigIntType: SRPBigIntProtocol>() -> BigIntType
    {
        // Short-circuit conversions between Data and BigIntType if possible
        if let impl = self as? SRPDataGenericImpl<BigIntType>
        {
            return impl._B
        }
        return BigIntType(serverPublicValue)
    }
}
