//
//  SRPDataGenericImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 20/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

struct SRPDataGenericImpl<BigIntType: SRPBigIntProtocol>: SRPData
{
    /// Password hash 'x' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _x = BigIntType()
    
    /// Client private value 'a' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _a = BigIntType()
    
    /// Client public value 'A' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _A = BigIntType()
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var _clientM = BigIntType()
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var _serverM = BigIntType()
    
    // Common data
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var _v = BigIntType()
    
    /// scrambler u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var _u = BigIntType()
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var _clientS = BigIntType()
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var _serverS = BigIntType()
    
    // Server specific data
    
    /// Multiplier 'k'. Computed as: k = H(N, g) (see SRP spec. in SRPProtocol.swift)
    var _k = BigIntType()
    
    /// Server private ephemeral value 'b' (see SRP spec. in SRPProtocol.swift)
    var _b = BigIntType()
    
    /// Server public ephemeral value 'B' (see SRP spec. in SRPProtocol.swift)
    var _B = BigIntType()
    
    /// Initializer to be used for client size data.
    ///
    /// - Parameters:
    ///   - x: Salted password hash (= H(s, p))
    ///   - a: Private ephemeral value 'a' (per SRP spec. above)
    ///   - A: Public ephemeral value 'A' (per SRP spec. above)
    init(x: BigIntType, a: BigIntType, A: BigIntType)
    {
        // Actually copy the values.
        _x = BigIntType(x)
        _a = BigIntType(a)
        _A = BigIntType(A)
    }
    
    
    /// Initializer to be used for the server side data.
    ///
    /// - Parameters:
    ///   - v: SRP verifier (received from the client)
    ///   - k: Parameter 'k' (per SRP spec. above)
    ///   - b: Private ephemeral value 'b' (per SRP spec. above)
    ///   - B: Public ephemeral value 'B' (per SRP spec. above)
    init(v: BigIntType, k: BigIntType, b: BigIntType, B: BigIntType)
    {
        _v = v
        _k = k
        _b = b
        _B = B
    }
    
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data {
        get {
            return _A.serialize()
        }
        set {
            _A = BigIntType(newValue)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    public var clientPrivateValue: Data {
        get {
            return _a.serialize()
        }
        set {
            _a = BigIntType(newValue)
        }
    }
    
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data {
        get {
            return _clientM.serialize()
        }
        set {
            _clientM = BigIntType(newValue)
        }
    }
    
    /// Password hash (see the spec. above)
    public var passwordHash: Data {
        get {
            return _x.serialize()
        }
        
        set {
            _x = BigIntType(newValue)
        }
    }
    
    /// Scrambler u
    public var scrambler: Data {
        get {
            return _u.serialize()
        }
        set {
            _u = BigIntType(newValue)
        }
    }
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var clientSecret: Data {
        get {
            return _clientS.serialize()
        }
        set {
            _clientS = BigIntType(newValue)
        }
    }
    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var verifier: Data {
        get {
            return _v.serialize()
        }
        set {
            _v = BigIntType(newValue)
        }
    }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data {
        get {
            return _B.serialize()
        }
        
        set {
            _B = BigIntType(newValue)
        }
    }
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    public var serverPrivateValue: Data {
        get {
            return _b.serialize()
        }
        set {
            _b = BigIntType(newValue)
        }
    }
    
    /// Server shared secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var serverSecret: Data {
        get {
            return _serverS.serialize()
        }
        set {
            _serverS = BigIntType(newValue)
        }
    }
    
    // Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift)
    public var multiplier: Data {
        get {
            return _k.serialize()
        }
        set {
            _k = BigIntType(newValue)
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var serverEvidenceMessage: Data {
        get {
            return _serverM.serialize()
        }
        
        set {
            _serverM = BigIntType(newValue)
        }
    }
}



