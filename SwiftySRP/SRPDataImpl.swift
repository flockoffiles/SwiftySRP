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
    var x: BigUInt
    var a: BigUInt
    var A: BigUInt
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientM: BigUInt
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverM: BigUInt
    
    // Common data
    /// SRP Verifier
    var v: BigUInt
    
    /// scrambler u = H(A, B)
    var u: BigUInt
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var clientS: BigUInt
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var serverS: BigUInt
    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var k: BigUInt
    
    /// Private ephemeral value 'b'
    var b: BigUInt
    
    /// Public ephemeral value 'B'
    var B: BigUInt
    
    
    /// Initializer to be used for client size data.
    ///
    /// - Parameters:
    ///   - x: Salted password hash (= H(s, p))
    ///   - a: Private ephemeral value 'a' (per SRP spec. above)
    ///   - A: Public ephemeral value 'A' (per SRP spec. above)
    init(x: BigUInt, a: BigUInt, A: BigUInt)
    {
        self.x = x
        self.a = a
        self.A = A
        
        self.v = 0
        self.b = 0
        self.k = 0
        self.B = 0
        self.u = 0
        self.clientS = 0
        self.serverS = 0
        self.clientM = 0
        self.serverM = 0
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
        self.v = v
        self.k = k
        self.b = b
        self.B = B
        
        self.x = 0
        self.a = 0
        self.A = 0
        self.u = 0
        self.clientS = 0
        self.serverS = 0
        self.clientM = 0
        self.serverM = 0
    }
    
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data {
        get {
            return self.A.serialize()
        }
        set {
            self.A = BigUInt(newValue)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    public var clientPrivateValue: Data {
        get {
            return self.a.serialize()
        }
        set {
            self.a = BigUInt(newValue)
        }
    }
    
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data {
        get {
            return self.clientM.serialize()
        }
        set {
            self.clientM = BigUInt(newValue)
        }
    }
    
    /// Password hash (see the spec. above)
    public var passwordHash: Data {
        get {
            return x.serialize()
        }
        
        set {
            x = BigUInt(newValue)
        }
    }
    
    /// Scrambler u
    public var scrambler: Data {
        get {
            return u.serialize()
        }
        set {
            u = BigUInt(newValue)
        }
    }
    
    public var clientSecret: Data {
        get {
            return clientS.serialize()
        }
        set {
            clientS = BigUInt(newValue)
        }
    }
    
    /// SRP Verifier.
    var verifier: Data {
        get {
            return self.v.serialize()
        }
        set {
            self.v = BigUInt(newValue)
        }
    }
    
    /// Server public value 'B' (see the spec. above)
    var serverPublicValue: Data {
        get {
            return self.B.serialize()
        }
        
        set {
            self.B = BigUInt(newValue)
        }
    }
    
    public var serverPrivateValue: Data {
        get {
            return b.serialize()
        }
        set {
            self.b = BigUInt(newValue)
        }
    }
    
    
    
    public var serverSecret: Data {
        get {
            return serverS.serialize()
        }
        set {
            self.serverS = BigUInt(newValue)
        }
    }
    
    // k
    public var multiplier: Data {
        get {
            return k.serialize()
        }
        set {
            self.k = BigUInt(newValue)
        }
    }
    
    
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverEvidenceMessage: Data {
        get {
            return self.serverM.serialize()
        }
        
        set {
            self.serverM = BigUInt(newValue)
        }
    }
    
    
}
