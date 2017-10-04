//
//  SRPError.swift
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

/// Various SRP related errors that can be thrown
public enum SRPError: String, Error, CustomStringConvertible, LocalizedError, CustomNSError
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
    case dataConversionError = "Data conversion error"
    
    public var description: String {
        return self.rawValue
    }
    
    /// A localized message describing what error occurred.
    public var errorDescription: String? {
        return self.rawValue
    }

    public static var customErrorDomain: String? = nil
    
    public static var errorDomain: String {
        return customErrorDomain ?? "SwiftySRP.SRPError"
    }
    
    public static var customErrorCodeMappingFunction: ((SRPError) -> Int)? = nil
    
    public var errorCode: Int
    {
        if let errorCodeMappingFunction = SRPError.customErrorCodeMappingFunction
        {
            return errorCodeMappingFunction(self)
        }
        switch self {
        case .invalidSalt:
            return 1
        case .invalidUserName:
            return 2
        case .invalidPassword:
            return 3
        case .invalidVerifier:
            return 4
        case .invalidClientPublicValue:
            return 5
        case .invalidServerPublicValue:
            return 6
        case .invalidClientPrivateValue:
            return 7
        case .invalidServerPrivateValue:
            return 8
        case .invalidPasswordHash:
            return 9
        case .invalidClientEvidenceMessage:
            return 10
        case .invalidServerEvidenceMessage:
            return 11
        case .invalidClientSharedSecret:
            return 12
        case .invalidServerSharedSecret:
            return 13
        case .configurationPrimeTooShort:
            return 14
        case .configurationGeneratorInvalid:
            return 15
        case .dataConversionError:
            return 16
        }
    }
    
}
