//
//  SRPDataImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt


/// SRP intermediate data (implementation)
struct SRPDataImpl: SRPData
{
    // Client specific data
    var uint_x: BigUInt
    var uint_a: BigUInt
    var uint_A: BigUInt
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var uint_clientM: BigUInt
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var uint_serverM: BigUInt
    
    // Common data
    /// SRP Verifier
    var uint_v: BigUInt
    
    /// scrambler u = H(A, B)
    var uint_u: BigUInt
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var uint_clientS: BigUInt
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var uint_serverS: BigUInt
    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var uint_k: BigUInt
    
    /// Private ephemeral value 'b'
    var uint_b: BigUInt
    
    /// Public ephemeral value 'B'
    var uint_B: BigUInt
    
    
    /// Initializer to be used for client size data.
    ///
    /// - Parameters:
    ///   - x: Salted password hash (= H(s, p))
    ///   - a: Private ephemeral value 'a' (per SRP spec. above)
    ///   - A: Public ephemeral value 'A' (per SRP spec. above)
    init(x: BigUInt, a: BigUInt, A: BigUInt)
    {
        self.uint_x = x
        self.uint_a = a
        self.uint_A = A
        
        self.uint_v = 0
        self.uint_b = 0
        self.uint_k = 0
        self.uint_B = 0
        self.uint_u = 0
        self.uint_clientS = 0
        self.uint_serverS = 0
        self.uint_clientM = 0
        self.uint_serverM = 0
    }
    
    
    /// Initializer to be used for the server side data.
    ///
    /// - Parameters:
    ///   - v: SRP verifier (received from the client)
    ///   - k: Parameter 'k' (per SRP spec. above)
    ///   - b: Private ephemeral value 'b' (per SRP spec. above)
    ///   - B: Public ephemeral value 'B' (per SRP spec. above)
    init(v: BigUInt, k: BigUInt, b: BigUInt, B: BigUInt)
    {
        self.uint_v = v
        self.uint_k = k
        self.uint_b = b
        self.uint_B = B
        
        self.uint_x = 0
        self.uint_a = 0
        self.uint_A = 0
        self.uint_u = 0
        self.uint_clientS = 0
        self.uint_serverS = 0
        self.uint_clientM = 0
        self.uint_serverM = 0
    }
    
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data {
        get {
            return uint_A.serialize()
        }
        set {
            uint_A = BigUInt(newValue)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    public var clientPrivateValue: Data {
        get {
            return uint_a.serialize()
        }
        set {
            uint_a = BigUInt(newValue)
        }
    }
    
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data {
        get {
            return uint_clientM.serialize()
        }
        set {
            uint_clientM = BigUInt(newValue)
        }
    }
    
    /// Password hash (see the spec. above)
    public var passwordHash: Data {
        get {
            return uint_x.serialize()
        }
        
        set {
            uint_x = BigUInt(newValue)
        }
    }
    
    /// Scrambler u
    public var scrambler: Data {
        get {
            return uint_u.serialize()
        }
        set {
            uint_u = BigUInt(newValue)
        }
    }
    
    public var clientSecret: Data {
        get {
            return uint_clientS.serialize()
        }
        set {
            uint_clientS = BigUInt(newValue)
        }
    }
    
    /// SRP Verifier.
    var verifier: Data {
        get {
            return uint_v.serialize()
        }
        set {
            uint_v = BigUInt(newValue)
        }
    }
    
    /// Server public value 'B' (see the spec. above)
    var serverPublicValue: Data {
        get {
            return uint_B.serialize()
        }
        
        set {
            uint_B = BigUInt(newValue)
        }
    }
    
    public var serverPrivateValue: Data {
        get {
            return uint_b.serialize()
        }
        set {
            uint_b = BigUInt(newValue)
        }
    }
    
    
    
    public var serverSecret: Data {
        get {
            return uint_serverS.serialize()
        }
        set {
            uint_serverS = BigUInt(newValue)
        }
    }
    
    // k
    public var multiplier: Data {
        get {
            return uint_k.serialize()
        }
        set {
            uint_k = BigUInt(newValue)
        }
    }
    
    
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverEvidenceMessage: Data {
        get {
            return uint_serverM.serialize()
        }
        
        set {
            uint_serverM = BigUInt(newValue)
        }
    }
    
}

/// Internal extension to short-circuit conversions between Data and BigUInt
/// in case the implementation of SRPData is SRPDataImpl (which uses BigUInt)
extension SRPData
{
    // Client specific data
    
    /// Password hash (see the spec. above)
    var x: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_x
            }
            return BigUInt(passwordHash)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    var a: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_a
            }
            return BigUInt(clientPrivateValue)
        }
    }
    
    /// Client public value 'A' (see the spec. above)
    var A: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_A
            }
            
            return BigUInt(clientPublicValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientM: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_clientM
            }
            
            return BigUInt(clientEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataImpl
            {
                impl.uint_clientM = newValue
                self = impl as! Self
            }
            else
            {
                clientEvidenceMessage = newValue.serialize()
            }
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverM: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_serverM
            }
            return BigUInt(serverEvidenceMessage)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_serverM = newValue
                self = impl as! Self
            }
            else
            {
                serverEvidenceMessage = newValue.serialize()
            }
        }
    }
    
    // Common data:
    
    /// SRP Verifier.
    var v: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_v
            }
            return BigUInt(verifier)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_v = newValue
                self = impl as! Self
            }
            else
            {
                self.verifier = newValue.serialize()
            }
        }
    }
    
    // u = H(A, B)
    var u: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_u
            }
            return BigUInt(scrambler)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_u = newValue
                self = impl as! Self
            }
            else
            {
                self.scrambler = newValue.serialize()
            }
        }
    }
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var clientS: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_clientS
            }
            return BigUInt(clientSecret)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_clientS = newValue
                self = impl as! Self
            }
            else
            {
                self.clientSecret = newValue.serialize()
            }
        }
    }
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var serverS: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_serverS
            }
            return BigUInt(serverSecret)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_serverS = newValue
                self = impl as! Self
            }
            else
            {
                self.serverSecret = newValue.serialize()
            }
        }
    }
    
    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var k: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_k
            }
            return BigUInt(multiplier)
        }
        set {
            if var impl = self as? SRPDataImpl
            {
                impl.uint_k = newValue
                self = impl as! Self
            }
            else
            {
                self.multiplier = newValue.serialize()
            }
        }
    }
    
    
    /// Server private value 'b' (see the spec. above)
    var b: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_b
            }
            return BigUInt(serverPrivateValue)
        }
    }
    
    
    /// Server public value 'B' (see the spec. above)
    var B: BigUInt {
        get {
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_B
            }
            return BigUInt(serverPublicValue)
        }
    }
    
}

