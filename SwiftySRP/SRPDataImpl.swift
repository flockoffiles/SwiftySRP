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
    
    /// Password hash 'x' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var uint_x: BigUInt
    
    /// Client private value 'a' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var uint_a: BigUInt
    
    /// Client public value 'A' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var uint_A: BigUInt
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var uint_clientM: BigUInt
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var uint_serverM: BigUInt
    
    // Common data
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var uint_v: BigUInt
    
    /// scrambler u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var uint_u: BigUInt
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var uint_clientS: BigUInt
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var uint_serverS: BigUInt
    
    // Server specific data
    
    /// Multiplier 'k'. Computed as: k = H(N, g) (see SRP spec. in SRPProtocol.swift)
    var uint_k: BigUInt
    
    /// Server private ephemeral value 'b' (see SRP spec. in SRPProtocol.swift)
    var uint_b: BigUInt
    
    /// Server public ephemeral value 'B' (see SRP spec. in SRPProtocol.swift)
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
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var clientSecret: Data {
        get {
            return uint_clientS.serialize()
        }
        set {
            uint_clientS = BigUInt(newValue)
        }
    }
    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var verifier: Data {
        get {
            return uint_v.serialize()
        }
        set {
            uint_v = BigUInt(newValue)
        }
    }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data {
        get {
            return uint_B.serialize()
        }
        
        set {
            uint_B = BigUInt(newValue)
        }
    }
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    public var serverPrivateValue: Data {
        get {
            return uint_b.serialize()
        }
        set {
            uint_b = BigUInt(newValue)
        }
    }
    
    /// Server shared secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var serverSecret: Data {
        get {
            return uint_serverS.serialize()
        }
        set {
            uint_serverS = BigUInt(newValue)
        }
    }
    
    // Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift)
    public var multiplier: Data {
        get {
            return uint_k.serialize()
        }
        set {
            uint_k = BigUInt(newValue)
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
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
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
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
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
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
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
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
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
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
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var serverM: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_serverM
            }
            return BigUInt(serverEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var v: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_v
            }
            return BigUInt(verifier)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    // Scrambler parameter 'u'. u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var u: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_u
            }
            return BigUInt(scrambler)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    /// Shared secret 'S' . Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var clientS: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_clientS
            }
            return BigUInt(clientSecret)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    /// Shared secret 'S'. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var serverS: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_serverS
            }
            return BigUInt(serverSecret)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    /// Multiplier parameter 'k'. Computed as: k = H(N, g) (see SRP spec. in SRPProtocol.swift)
    var k: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_k
            }
            return BigUInt(multiplier)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
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
    
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    var b: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_b
            }
            return BigUInt(serverPrivateValue)
        }
    }
    
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var B: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataImpl
            {
                return impl.uint_B
            }
            return BigUInt(serverPublicValue)
        }
    }
}

