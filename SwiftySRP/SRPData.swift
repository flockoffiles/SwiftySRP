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
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    var clientPublicValue: Data { get set }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var clientEvidenceMessage: Data { get set }
    
    /// SRP Verifier. (see SRP spec. in SRPProtocol.swift)
    var verifier: Data { get set }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var serverEvidenceMessage: Data { get set }
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
    var passwordHash: Data { get }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    var clientPrivateValue: Data { get }
    
    /// Scrambler parameter 'u' = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var scrambler: Data { get set }
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift)
    var clientSecret: Data { get set }
    
    /// Server secret 'S' (see SRP spec. in SRPProtocol.swift)
    var serverSecret: Data { get set }
    
    /// Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift)
    var multiplier: Data { get set }
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    var serverPrivateValue: Data { get }
}


