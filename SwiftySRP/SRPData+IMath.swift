//
//  SRPData+IMath.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import imath

/// Internal extension to short-circuit conversions between Data and SRPMpzT
/// in case the implementation of SRPData is SRPDataIMathImpl (which uses SRPMpzT)
extension SRPData
{
    // Client specific data
    
    /// Password hash 'x' (see SRP spec. in SRPProtocol.swift)
    var mpz_x: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_x
            }
            return SRPMpzT(passwordHash)
        }
    }
    
    /// Client private value 'a' (see SRP spec. in SRPProtocol.swift)
    var mpz_a: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_a
            }
            return SRPMpzT(clientPrivateValue)
        }
    }
    
    /// Client public value 'A' (see SRP spec. in SRPProtocol.swift)
    var mpz_A: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_A
            }
            
            return SRPMpzT(clientPublicValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S (see SRP spec. in SRPProtocol.swift)
    var mpz_clientM: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_clientM
            }
            
            return SRPMpzT(clientEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_clientM = newValue
                self = impl as! Self
            }
            else
            {
                clientEvidenceMessage = newValue.serialize()
            }
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret. (see SRP spec. in SRPProtocol.swift)
    var mpz_serverM: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_serverM
            }
            return SRPMpzT(serverEvidenceMessage)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_serverM = newValue
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
    var mpz_v: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_v
            }
            return SRPMpzT(verifier)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_v = newValue
                self = impl as! Self
            }
            else
            {
                self.verifier = newValue.serialize()
            }
        }
    }
    
    // Scrambler parameter 'u'. u = H(A, B) (see SRP spec. in SRPProtocol.swift)
    var mpz_u: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_u
            }
            return SRPMpzT(scrambler)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_u = newValue
                self = impl as! Self
            }
            else
            {
                self.scrambler = newValue.serialize()
            }
        }
    }
    
    /// Shared secret 'S' . Computed on the client as: S = (B - kg^x) ^ (a + ux) (see SRP spec. in SRPProtocol.swift)
    var mpz_clientS: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_clientS
            }
            return SRPMpzT(clientSecret)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_clientS = newValue
                self = impl as! Self
            }
            else
            {
                self.clientSecret = newValue.serialize()
            }
        }
    }
    
    /// Shared secret 'S'. Computed on the server as: S = (Av^u) ^ b (see SRP spec. in SRPProtocol.swift)
    var mpz_serverS: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_serverS
            }
            return SRPMpzT(serverSecret)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_serverS = newValue
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
    var mpz_k: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_k
            }
            return SRPMpzT(multiplier)
        }
        set {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if var impl = self as? SRPDataIMathImpl
            {
                impl.mpz_k = newValue
                self = impl as! Self
            }
            else
            {
                self.multiplier = newValue.serialize()
            }
        }
    }
    
    
    /// Server private value 'b' (see SRP spec. in SRPProtocol.swift)
    var mpz_b: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_b
            }
            return SRPMpzT(serverPrivateValue)
        }
    }
    
    
    /// Server public value 'B' (see SRP spec. in SRPProtocol.swift)
    var mpz_B: SRPMpzT {
        get {
            // Short-circuit conversions between Data and SRPMpzT if possible
            if let impl = self as? SRPDataIMathImpl
            {
                return impl.mpz_B
            }
            return SRPMpzT(serverPublicValue)
        }
    }
}

