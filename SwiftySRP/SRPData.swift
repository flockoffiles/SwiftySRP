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

/// Protocol defining SRP intermediate data.
public protocol SRPData: Codable {
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    var clientPublicValue: Data { get set }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var clientEvidenceMessage: Data { get set }
    
    /// SRP Verifier. (see SRP spec. in SRPProtocol.swift)
    var verifier: Data { get set }
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var serverPublicValue: Data { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message,
    /// and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
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

extension SRPData {
    public func wrappedClientPublicValue<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { clientPublicValue })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(clientPublicValue: DataWrapperType) {
        clientPublicValue.map {
            self.clientPublicValue = $0
        }
    }

    public func wrappedClientEvidenceMessage<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { clientEvidenceMessage })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(clientEvidenceMessage: DataWrapperType) {
        clientEvidenceMessage.map {
            self.clientEvidenceMessage = $0
        }
    }

    public func wrappedVerifier<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { verifier })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(verifier: DataWrapperType) {
        verifier.map {
            self.verifier = $0
        }
    }

    public func wrappedServerPublicValue<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { serverPublicValue })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(serverPublicValue: DataWrapperType) {
        serverPublicValue.map {
            self.serverPublicValue = $0
        }
    }
    
    public func wrappedServerEvidenceMessage<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { serverEvidenceMessage })
    }

    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(serverEvidenceMessage: DataWrapperType) {
        serverEvidenceMessage.map {
            self.serverEvidenceMessage = $0
        }
    }
    
    public func wrappedScrambler<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { scrambler })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(scrambler: DataWrapperType) {
        scrambler.map {
            self.scrambler = $0
        }
    }
    
    public func wrappedClientSecret<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { clientSecret })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(clientSecret: DataWrapperType) {
        clientSecret.map {
            self.clientSecret = $0
        }
    }
    
    public func wrappedServerSecret<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { serverSecret })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(serverSecret: DataWrapperType) {
        serverSecret.map {
            self.serverSecret = $0
        }
    }
    
    public func wrappedMultiplier<DataWrapperType: SRPDataWrapperProtocol>() -> DataWrapperType {
        return DataWrapperType(dataFunc: { multiplier })
    }
    
    mutating public func set<DataWrapperType: SRPDataWrapperProtocol>(multiplier: DataWrapperType) {
        multiplier.map {
            self.multiplier = $0
        }
    }
}
