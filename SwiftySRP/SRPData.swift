//
//  SRPData.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

/// Protocol defining SRP intermediate data.
public protocol SRPData
{
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data { get set }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data { get set }
    
    /// SRP Verifier.
    var verifier: Data { get set }
    
    /// Server public value 'B' (see the spec. above)
    var serverPublicValue: Data { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverEvidenceMessage: Data { get set }
    
    /// Password hash (see the spec. above)
    var passwordHash: Data { get }
    
    /// Client private value 'a' (see the spec. above)
    var clientPrivateValue: Data { get }
    
    // u = H(A, B)
    var scrambler: Data { get set }
    
    var clientSecret: Data { get set }
    
    var serverSecret: Data { get set }
    
    var multiplier: Data { get set }
    
    var serverPrivateValue: Data { get }
}


