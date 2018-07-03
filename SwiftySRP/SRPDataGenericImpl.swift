//
//  SRPDataGenericImpl.swift
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
import FFDataWrapper

/// Specific implementation of SRP data for supported big integer types (they must conform to SRPBigIntProtocol)
public struct SRPDataGenericImpl<BigIntType: SRPBigIntProtocol>: SRPData
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
    public init(x: BigIntType, a: BigIntType, A: BigIntType)
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
    public init(v: BigIntType, k: BigIntType, b: BigIntType, B: BigIntType)
    {
        _v = v
        _k = k
        _b = b
        _B = B
    }
    
    /// Client public value 'A' (see the spec. above)
    public var clientPublicValue: Data {
        get {
            return _A.serialize()
        }
        set {
            _A = BigIntType(newValue)
        }
    }
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedClientPublicValue: FFDataWrapper {
        get {
            return _A.wrappedSerialize()
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
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    public var wrappedClientPrivateValue: FFDataWrapper {
        get {
            return _a.wrappedSerialize()
        }
        set {
            _a = BigIntType(newValue)
        }
    }

    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    public var clientEvidenceMessage: Data {
        get {
            return _clientM.serialize()
        }
        set {
            _clientM = BigIntType(newValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    public var wrappedClientEvidenceMessage: FFDataWrapper {
        get {
            return _clientM.wrappedSerialize()
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
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedPasswordHash: FFDataWrapper {
        get {
            return _x.wrappedSerialize()
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
    
    /// Scrambler parameter 'u' = H(A, B) (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedScrambler: FFDataWrapper {
        get {
            return _u.wrappedSerialize()
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
    
    /// Client secret 'S' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedClientSecret: FFDataWrapper {
        get {
            return _clientS.wrappedSerialize()
        }
        set {
            _clientS = BigIntType(newValue)
        }
    }

    
    /// SRP Verifier 'v' (see SRP spec. in SRPProtocol.swift)
    public var verifier: Data {
        get {
            return _v.serialize()
        }
        set {
            _v = BigIntType(newValue)
        }
    }
    
    /// SRP Verifier. (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedVerifier: FFDataWrapper {
        get {
            return _v.wrappedSerialize()
        }
        set {
            _v = BigIntType(newValue)
        }
    }

    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    public var serverPublicValue: Data {
        get {
            return _B.serialize()
        }
        
        set {
            _B = BigIntType(newValue)
        }
    }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedServerPublicValue: FFDataWrapper {
        get {
            return _B.wrappedSerialize()
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
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedServerPrivateValue: FFDataWrapper {
        get {
            return _b.wrappedSerialize()
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
    
    /// Server secret 'S' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedServerSecret: FFDataWrapper {
        get {
            return _serverS.wrappedSerialize()
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
    
    /// Multiplier parameter 'k' (see SRP spec. in SRPProtocol.swift). This version returns a wrapped value (more secure).
    public var wrappedMultiplier: FFDataWrapper {
        get {
            return _k.wrappedSerialize()
        }
        set {
            _k = BigIntType(newValue)
        }
    }

    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    public var serverEvidenceMessage: Data {
        get {
            return _serverM.serialize()
        }
        
        set {
            _serverM = BigIntType(newValue)
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    /// This version returns a wrapped value (more secure).
    public var wrappedServerEvidenceMessage: FFDataWrapper {
        get {
            return _serverM.wrappedSerialize()
        }
        set {
            _serverM = BigIntType(newValue)
        }
    }
    
    enum CodingKeys: String, CodingKey {
        case wrappedClientPublicValue
        case wrappedClientEvidenceMessage
        case wrappedVerifier
        case wrappedServerPublicValue
        case wrappedServerEvidenceMessage
        case wrappedPasswordHash
        case wrappedClientPrivateValue
        case wrappedScrambler
        case wrappedClientSecret
        case wrappedServerSecret
        case wrappedMultiplier
        case wrappedServerPrivateValue
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(self.wrappedClientPublicValue, forKey: .wrappedClientPublicValue)
        try container.encode(self.wrappedClientEvidenceMessage, forKey: .wrappedClientEvidenceMessage)
        try container.encode(self.wrappedVerifier, forKey: .wrappedVerifier)
        try container.encode(self.wrappedServerPublicValue, forKey: .wrappedServerPublicValue)
        try container.encode(self.wrappedServerEvidenceMessage, forKey: .wrappedServerEvidenceMessage)
        try container.encode(self.wrappedPasswordHash, forKey: .wrappedPasswordHash)
        try container.encode(self.wrappedClientPrivateValue, forKey: .wrappedClientPrivateValue)
        try container.encode(self.wrappedScrambler, forKey: .wrappedScrambler)
        try container.encode(self.wrappedClientSecret, forKey: .wrappedClientSecret)
        try container.encode(self.wrappedServerSecret, forKey: .wrappedServerSecret)
        try container.encode(self.wrappedMultiplier, forKey: .wrappedMultiplier)
        try container.encode(self.wrappedServerPrivateValue, forKey: .wrappedServerPrivateValue)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.wrappedClientPublicValue = try container.decode(FFDataWrapper.self, forKey: .wrappedClientPublicValue)
        self.wrappedClientEvidenceMessage = try container.decode(FFDataWrapper.self, forKey: .wrappedClientEvidenceMessage)
        self.wrappedVerifier = try container.decode(FFDataWrapper.self, forKey: .wrappedVerifier)
        self.wrappedServerPublicValue = try container.decode(FFDataWrapper.self, forKey: .wrappedServerPublicValue)
        self.wrappedServerEvidenceMessage = try container.decode(FFDataWrapper.self, forKey: .wrappedServerEvidenceMessage)
        self.wrappedPasswordHash = try container.decode(FFDataWrapper.self, forKey: .wrappedPasswordHash)
        self.wrappedClientPrivateValue = try container.decode(FFDataWrapper.self, forKey: .wrappedClientPrivateValue)
        self.wrappedScrambler = try container.decode(FFDataWrapper.self, forKey: .wrappedScrambler)
        self.wrappedClientSecret = try container.decode(FFDataWrapper.self, forKey: .wrappedClientSecret)
        self.wrappedServerSecret = try container.decode(FFDataWrapper.self, forKey: .wrappedServerSecret)
        self.wrappedMultiplier = try container.decode(FFDataWrapper.self, forKey: .wrappedMultiplier)
        self.wrappedServerPrivateValue = try container.decode(FFDataWrapper.self, forKey: .wrappedServerPrivateValue)
    }
}
