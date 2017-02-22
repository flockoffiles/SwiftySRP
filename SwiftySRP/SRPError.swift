//
//  SRPError.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 22/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

/// Various SRP related errors that can be thrown
enum SRPError: String, Error, CustomStringConvertible
{
    case invalidSalt = "SRP salt is too short"
    case invalidUserName = "SRP user name cannot be empty"
    case invalidPassword = "SRP password cannot be empty"
    case invalidVerifier = "SRP verifier is invalid"
    case invalidClientPublicValue = "SRP client public value is invalid"
    case invalidServerPublicValue = "SRP server public value is invalid"
    case invalidClientPrivateValue = "SRP client private value is invalid"
    case invalidServerPrivateValue = "SRP server private value is invalid"
    case invalidPasswordHash = "SRP password hash is invalid"
    case invalidClientEvidenceMessage = "SRP client evidence message is invalid"
    case invalidServerEvidenceMessage = "SRP server evidence message is invalid"
    case invalidClientSharedSecret = "SRP client shared secret is invalid"
    case invalidServerSharedSecret = "SRP server shared secret is invalid"
    
    case configurationPrimeTooShort = "SRP configuration safe prime is too short"
    case configurationGeneratorInvalid = "SRP generator is invalid"
    
    var description: String {
        return self.rawValue
    }
}
