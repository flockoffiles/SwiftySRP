//
//  SRPProtocol.swift
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

// SPR Design spec: http://srp.stanford.edu/design.html
// SRP RFC: https://tools.ietf.org/html/rfc5054
//    N    A large safe prime (N = 2q+1, where q is prime)
//    All arithmetic is done modulo N.
//
//    g    A generator modulo N
//    k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
//    s    User's salt
//    I    Username
//    p    Cleartext Password
//    H()  One-way hash function
//        ^    (Modular) Exponentiation
//    u    Random scrambling parameter
//    a,b  Secret ephemeral values
//    A,B  Public ephemeral values
//    x    Private key (derived from p and s)
//    v    Password verifier

//    The host stores passwords using the following formula:
//    x = H(s, p)               (s is chosen randomly)
//    v = g^x                   (computes password verifier)
//    The host then keeps {I, s, v} in its password database. The authentication protocol itself goes as follows:
//    User -> Host:  I, A = g^a                  (identifies self, a = random number)
//    Host -> User:  s, B = kv + g^b             (sends salt, b = random number)
//
//    Both:  u = H(A, B)
//
//    User:  x = H(s, p)                 (user enters password)
//    NOTE: BouncyCastle does it differently because of the user name involved:
//           x = H(s | H(I | ":" | p))  (| means concatenation)
//
//    User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
//    User:  K = H(S)
//
//    Host:  S = (Av^u) ^ b              (computes session key)
//    Host:  K = H(S)
//    Now the two parties have a shared, strong session key K. To complete authentication, they need to prove to each other that their keys match. One possible way:
//    User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
//    Host -> User:  H(A, M, K)
//    The two parties also employ the following safeguards:
//    The user will abort if he receives B == 0 (mod N) or u == 0.
//    The host will abort if it detects that A == 0 (mod N).
//    The user must show his proof of K first. If the server detects that the user's proof is incorrect, it must abort without showing its own proof of K.


public protocol SRPProtocol
{
    /// Configuration for this protocol instance.
    var configuration: SRPConfiguration { get }
    
    /// Compute the verifier and client credentials.
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRPData with parameters v, x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    func verifier(s: Data, I: Data,  p: Data) throws -> SRPData
    
    /// Compute the verifier and client credentials.
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRPData with parameters v, x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    func verifier(s: FFDataWrapper, I: FFDataWrapper,  p: FFDataWrapper) throws -> SRPData

    /// Generate client credentials (parameters x, a, and A) from the SRP salt, user name (I), and password (p)
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRP data with parameters x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    func generateClientCredentials(s: Data, I: Data, p: Data) throws -> SRPData
    
    /// Generate client credentials (parameters x, a, and A) from the SRP salt, user name (I), and password (p)
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRP data with parameters x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    func generateClientCredentials(s: FFDataWrapper, I: FFDataWrapper, p: FFDataWrapper) throws -> SRPData
    
    /// Calculate the shared secret on the client side: S = (B - kg^x) ^ (a + ux)
    ///
    /// - Parameter srpData: SRP data to use in the calculation.
    ///   Must have the following parameters populated and valid: B (received from the server), A (computed previously), a, x
    /// - Returns: SRPData with parameter S populated
    /// - Throws: SRPError if some of the input parameters is not set or invalid.
    func calculateClientSecret(srpData: SRPData) throws -> SRPData
    
    /// Compute the client evidence message.
    /// NOTE: This is different from the spec. above and is done the BouncyCastle way:
    /// M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    /// - Parameter srpData: SRP data to use in the calculation.
    ///   Must have the following fields populated:
    ///   - a: Private ephemeral value a (per spec. above)
    ///   - A: Public ephemeral value A (per spec. above)
    ///   - x: Identity hash (computed the BouncyCastle way)
    ///   - B: Server public ephemeral value B (per spec. above)
    /// - Returns: SRPData with the client evidence message populated.
    /// - Throws: SRPError if some of the required parameters are invalid.
    func clientEvidenceMessage(srpData: SRPData) throws -> SRPData
    
    /// Verify the client evidence message (received from the client)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: A, B, clientM, serverS
    /// - Throws: SRPError in case verification fails or when some of the required parameters are invalid.
    func verifyClientEvidenceMessage(srpData: SRPData) throws
    
    /// Calculate the shared key (client side) in the standard way: sharedKey = H(clientS)
    ///
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateClientSharedKey(srpData: SRPData) throws -> Data

    /// Calculate the shared key (client side) in the standard way: sharedKey = H(clientS)
    /// This version returns a wrapped version (more secure).
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateClientSharedKey(srpData: SRPData) throws -> FFDataWrapper

    /// Calculate the shared key (client side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateClientSharedKey(srpData: SRPData, salt: Data) throws -> Data
    
    /// Calculate the shared key (client side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// This version returns a wrapped version (more secure).
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateClientSharedKey(srpData: SRPData, salt: FFDataWrapper) throws -> FFDataWrapper

    /// Generate the server side SRP parameters. This method normally will NOT be used by the client.
    /// It's included here for testing purposes.
    /// - Parameter verifier: SRP verifier received from the client.
    /// - Returns: SRP data with parameters v, k, b, and B populated.
    /// - Throws: SRPError if the verifier or configuration is invalid.
    func generateServerCredentials(verifier: Data) throws -> SRPData
    
    /// Calculate the shared secret on the server side: S = (Av^u) ^ b
    ///
    /// - Parameter srpData: SRPData with the following parameters populated: A, v, b, B
    /// - Returns: SRPData with the computed u and serverS
    /// - Throws: SRPError if some of the required parameters are invalid.
    func calculateServerSecret(srpData: SRPData) throws -> SRPData
    
    /// Compute the server evidence message.
    /// NOTE: This is different from the spec above and is done the BouncyCastle way:
    /// M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    /// - Parameter srpData: SRP Data with the following fields populated:
    ///   - A: Client value A
    ///   - v: Password verifier v (per spec above)
    ///   - b: Private ephemeral value b
    ///   - B: Public ephemeral value B
    ///   - clientM: Client evidence message
    /// - Returns: SRPData with the computed server evidence message field populated.
    /// - Throws: SRPError if some of the required parameters are invalid.
    func serverEvidenceMessage(srpData: SRPData) throws -> SRPData
    
    /// Verify the server evidence message (received from the server)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: serverM, clientM, A, clientS
    /// - Throws: SRPError if verification fails or if some of the input parameters is invalid.
    func verifyServerEvidenceMessage(srpData: SRPData) throws
    
    /// Calculate the shared key (server side) in the standard way: sharedKey = H(serverS)
    ///
    /// - Parameter srpData: SRPData with serverS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateServerSharedKey(srpData: SRPData) throws -> Data

    /// Calculate the shared key (server side) in the standard way: sharedKey = H(serverS)
    /// This version returns a wrapped version (more secure).
    ///
    /// - Parameter srpData: SRPData with serverS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateServerSharedKey(srpData: SRPData) throws -> FFDataWrapper

    /// Calculate the shared key (server side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateServerSharedKey(srpData: SRPData, salt: Data) throws -> Data

    /// Calculate the shared key (server side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// This version returns a wrapped version (more secure).
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateServerSharedKey(srpData: SRPData, salt: FFDataWrapper) throws -> FFDataWrapper

}


