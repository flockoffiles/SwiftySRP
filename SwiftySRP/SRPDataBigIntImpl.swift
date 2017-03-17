//
//  SRPDataBigIntImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt


/// SRP intermediate data (implementation)
struct SRPDataBigIntImpl: SRPData
{
    // Client specific data
    
    /// Password hash 'x' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _x: BigUInt = 0
    
    /// Client private value 'a' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _a: BigUInt = 0
    
    /// Client public value 'A' as BigUInt (see SRP spec. in SRPProtocol.swift)
    var _A: BigUInt = 0
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var _clientM: BigUInt = 0
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var _serverM: BigUInt = 0
    
    // Common data
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var _v: BigUInt = 0
    
    /// scrambler u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var _u: BigUInt = 0
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var _clientS: BigUInt = 0
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var _serverS: BigUInt = 0
    
    // Server specific data
    
    /// Multiplier 'k'. Computed as: k = H(N, g) (see SRP spec. in SRPProtocol.swift)
    var _k: BigUInt = 0
    
    /// Server private ephemeral value 'b' (see SRP spec. in SRPProtocol.swift)
    var _b: BigUInt = 0
    
    /// Server public ephemeral value 'B' (see SRP spec. in SRPProtocol.swift)
    var _B: BigUInt = 0
    
    
    /// Initializer to be used for client size data.
    ///
    /// - Parameters:
    ///   - x: Salted password hash (= H(s, p))
    ///   - a: Private ephemeral value 'a' (per SRP spec. above)
    ///   - A: Public ephemeral value 'A' (per SRP spec. above)
    init(x: BigUInt, a: BigUInt, A: BigUInt)
    {
        _x = x
        _a = a
        _A = A
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
            _A = BigUInt(newValue)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    public var clientPrivateValue: Data {
        get {
            return _a.serialize()
        }
        set {
            _a = BigUInt(newValue)
        }
    }
    
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data {
        get {
            return _clientM.serialize()
        }
        set {
            _clientM = BigUInt(newValue)
        }
    }
    
    /// Password hash (see the spec. above)
    public var passwordHash: Data {
        get {
            return _x.serialize()
        }
        
        set {
            _x = BigUInt(newValue)
        }
    }
    
    /// Scrambler u
    public var scrambler: Data {
        get {
            return _u.serialize()
        }
        set {
            _u = BigUInt(newValue)
        }
    }
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var clientSecret: Data {
        get {
            return _clientS.serialize()
        }
        set {
            _clientS = BigUInt(newValue)
        }
    }
    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    var verifier: Data {
        get {
            return _v.serialize()
        }
        set {
            _v = BigUInt(newValue)
        }
    }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data {
        get {
            return _B.serialize()
        }
        
        set {
            _B = BigUInt(newValue)
        }
    }
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    public var serverPrivateValue: Data {
        get {
            return _b.serialize()
        }
        set {
            _b = BigUInt(newValue)
        }
    }
    
    /// Server shared secret 'S' (see SRP spec. in SRPProtocol.swift)
    public var serverSecret: Data {
        get {
            return _serverS.serialize()
        }
        set {
            _serverS = BigUInt(newValue)
        }
    }
    
    // Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift)
    public var multiplier: Data {
        get {
            return _k.serialize()
        }
        set {
            _k = BigUInt(newValue)
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var serverEvidenceMessage: Data {
        get {
            return _serverM.serialize()
        }
        
        set {
            _serverM = BigUInt(newValue)
        }
    }
    
}

