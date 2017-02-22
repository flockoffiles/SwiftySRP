//
//  SRPData+Extensions.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

extension SRPData
{
    // Client specific data
    
    /// Password hash (see the spec. above)
    var x: BigUInt {
        get {
            return BigUInt(passwordHash)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    var a: BigUInt {
        get {
            return BigUInt(clientPrivateValue)
        }
    }
    
    /// Client public value 'A' (see the spec. above)
    var A: BigUInt {
        get {
            return BigUInt(clientPublicValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientM: BigUInt {
        get {
            return BigUInt(clientEvidenceMessage)
        }
        set {
            clientEvidenceMessage = newValue.serialize()
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverM: BigUInt {
        get {
            return BigUInt(serverEvidenceMessage)
        }
        set {
            serverEvidenceMessage = newValue.serialize()
        }
    }
    
    // Common data:
    
    /// SRP Verifier.
    var v: BigUInt {
        get {
            return BigUInt(verifier)
        }
        set {
            self.verifier = newValue.serialize()
        }
    }
    
    // u = H(A, B)
    var u: BigUInt {
        get {
            return BigUInt(scrambler)
        }
        set {
            self.scrambler = newValue.serialize()
        }
    }
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var clientS: BigUInt {
        get {
            return BigUInt(clientSecret)
        }
        set {
            self.clientSecret = newValue.serialize()
        }
    }
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var serverS: BigUInt {
        get {
            return BigUInt(serverSecret)
        }
        set {
            self.serverSecret = newValue.serialize()
        }
    }
    
    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var k: BigUInt {
        get {
            return BigUInt(multiplier)
        }
        set {
            self.multiplier = newValue.serialize()
        }
    }
    
    
    /// Server private value 'b' (see the spec. above)
    var b: BigUInt {
        get {
            return BigUInt(serverPrivateValue)
        }
    }
    
    
    /// Server public value 'B' (see the spec. above)
    var B: BigUInt {
        get {
            return BigUInt(serverPublicValue)
        }
    }
    
}
