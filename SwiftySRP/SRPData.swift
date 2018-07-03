//
//  SRPData.swift
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

/// Protocol defining SRP intermediate data.
public protocol SRPData: Codable
{
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    var clientPublicValue: Data { get set }
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedClientPublicValue: FFDataWrapper { get set }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var clientEvidenceMessage: Data { get set }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    var wrappedClientEvidenceMessage: FFDataWrapper { get set }
    
    /// SRP Verifier. (see SRP spec. in SRPProtocol.swift)
    var verifier: Data { get set }
    
    /// SRP Verifier. (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedVerifier: FFDataWrapper { get set }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data { get set }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedServerPublicValue: FFDataWrapper { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var serverEvidenceMessage: Data { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    var wrappedServerEvidenceMessage: FFDataWrapper { get set }
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
    var passwordHash: Data { get }
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedPasswordHash: FFDataWrapper { get }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    var clientPrivateValue: Data { get }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    var wrappedClientPrivateValue: FFDataWrapper { get }
    
    /// Scrambler parameter 'u' = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var scrambler: Data { get set }
    
    /// Scrambler parameter 'u' = H(A, B) (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedScrambler: FFDataWrapper { get set }
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift)
    var clientSecret: Data { get set }
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedClientSecret: FFDataWrapper { get set }
    
    /// Server secret 'S' (see SRP spec. in SRPProtocol.swift)
    var serverSecret: Data { get set }

    /// Server secret 'S' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedServerSecret: FFDataWrapper { get set }

    /// Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift)
    var multiplier: Data { get set }

    /// Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedMultiplier: FFDataWrapper { get set }

    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    var serverPrivateValue: Data { get }
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    var wrappedServerPrivateValue: FFDataWrapper { get }
}
