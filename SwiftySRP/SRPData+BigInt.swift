//
//  SRPData+BigInt.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt

/// Internal extension to short-circuit conversions between Data and BigUInt
/// in case the implementation of SRPData is SRPDataBigIntImpl (which uses BigUInt)
extension SRPData
{
    // Client specific data
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
    var uint_x: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._x
            }
            return BigUInt(passwordHash)
        }
    }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    var uint_a: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._a
            }
            return BigUInt(clientPrivateValue)
        }
    }
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    var uint_A: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._A
            }
            
            return BigUInt(clientPublicValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var uint_clientM: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._clientM
            }
            
            return BigUInt(clientEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._clientM = newValue
                self = impl as! Self
            }
            else
            {
                clientEvidenceMessage = newValue.serialize()
            }
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var uint_serverM: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._serverM
            }
            return BigUInt(serverEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._serverM = newValue
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
    var uint_v: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._v
            }
            return BigUInt(verifier)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._v = newValue
                self = impl as! Self
            }
            else
            {
                self.verifier = newValue.serialize()
            }
        }
    }
    
    // Scrambler parameter 'u'. u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var uint_u: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._u
            }
            return BigUInt(scrambler)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._u = newValue
                self = impl as! Self
            }
            else
            {
                self.scrambler = newValue.serialize()
            }
        }
    }
    
    /// Shared secret 'S' . Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var uint_clientS: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._clientS
            }
            return BigUInt(clientSecret)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._clientS = newValue
                self = impl as! Self
            }
            else
            {
                self.clientSecret = newValue.serialize()
            }
        }
    }
    
    /// Shared secret 'S'. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var uint_serverS: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._serverS
            }
            return BigUInt(serverSecret)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._serverS = newValue
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
    var uint_k: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._k
            }
            return BigUInt(multiplier)
        }
        set {
            // Short-circuit conversions between Data and BigUInt if possible
            if var impl = self as? SRPDataBigIntImpl
            {
                impl._k = newValue
                self = impl as! Self
            }
            else
            {
                self.multiplier = newValue.serialize()
            }
        }
    }
    
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    var uint_b: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._b
            }
            return BigUInt(serverPrivateValue)
        }
    }
    
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var uint_B: BigUInt {
        get {
            // Short-circuit conversions between Data and BigUInt if possible
            if let impl = self as? SRPDataBigIntImpl
            {
                return impl._B
            }
            return BigUInt(serverPublicValue)
        }
    }
}

