//
//  SRPIMathImpl.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 16/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import imath

/// Implementation of the SRP protocol. Although it's primarily intended to be used on the client side, it includes the server side methods
/// as well (for testing purposes).
public struct SRPIMathImpl: SRPProtocol
{
    /// SRP configuration. Defines the prime N and generator g to be used, and also the relevant hashing functions.
    public var configuration: SRPConfiguration
    
    /// Generate client credentials (parameters x, a, and A) from the SRP salt, user name (I), and password (p)
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRP data with parameters x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    public func generateClientCredentials(s: Data, I: Data, p: Data) throws -> SRPData
    {
        // TODO: There may be more stringent requirements about salt.
        try configuration.validate()
        guard !s.isEmpty else { throw SRPError.invalidSalt }
        guard !I.isEmpty else { throw SRPError.invalidUserName }
        guard !p.isEmpty else { throw SRPError.invalidPassword }
        
        let value_x: SRPMpzT = x(s: s, I: I, p: p)
        let value_a: SRPMpzT = SRPMpzT(configuration.clientPrivateValue())
        
        // A = g^a
        let value_A = SRPMpzT(configuration.generator).power(value_a, modulus: SRPMpzT(configuration.modulus))
        
        return SRPDataIMathImpl(x: value_x, a: value_a, A: value_A)
    }
    
    
    /// Generate the server side SRP parameters. This method normally will NOT be used by the client.
    /// It's included here for testing purposes.
    /// - Parameter verifier: SRP verifier received from the client.
    /// - Returns: SRP data with parameters v, k, b, and B populated.
    /// - Throws: SRPError if the verifier or configuration is invalid.
    public func generateServerCredentials(verifier: Data) throws -> SRPData
    {
        guard !verifier.isEmpty else { throw SRPError.invalidVerifier }
        try configuration.validate()
        let N = SRPMpzT(configuration.modulus)
        let g = SRPMpzT(configuration.generator)
        let v:SRPMpzT = SRPMpzT(verifier)
        let k:SRPMpzT = hashPaddedPair(digest: configuration.digest, N: N, n1: N, n2: SRPMpzT(configuration.generator))
        let b:SRPMpzT = SRPMpzT(configuration.serverPrivateValue())
        
        // B = kv + g^b
        let B = (((k * v) % N) + g.power(b, modulus: N)) % N
        
        return SRPDataIMathImpl(v:v, k:k, b:b, B:B)
    }
    
    
    /// Compute the verifier and client credentials.
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRPData with parameters v, x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    public func verifier(s: Data, I: Data,  p: Data) throws -> SRPData
    {
        // let valueX = x(s:s, I:I, p:p)
        var srpData = try generateClientCredentials(s: s, I: I, p: p)
        let g = SRPMpzT(configuration.generator)
        let N = SRPMpzT(configuration.modulus)
        srpData.mpz_v = g.power(srpData.mpz_x, modulus:N)
        
        return srpData
    }
    
    
    /// Calculate the shared secret on the client side: S = (B - kg^x) ^ (a + ux)
    ///
    /// - Parameter srpData: SRP data to use in the calculation.
    ///   Must have the following parameters populated and valid: B (received from the server), A (computed previously), a, x
    /// - Returns: SRPData with parameter S populated
    /// - Throws: SRPError if some of the input parameters is not set or invalid.
    public func calculateClientSecret(srpData: SRPData) throws -> SRPData
    {
        try configuration.validate()
        let N = configuration.mpz_N
        let g = configuration.mpz_g
        var resultData = srpData
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.mpz_B % N) > SRPMpzT(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.mpz_a > SRPMpzT(0) else { throw SRPError.invalidClientPrivateValue }
        guard resultData.mpz_x > SRPMpzT(0) else { throw SRPError.invalidPasswordHash }
        
        resultData.mpz_u = hashPaddedPair(digest: configuration.digest, N: N, n1: resultData.mpz_A, n2: resultData.mpz_B)
        resultData.mpz_k = hashPaddedPair(digest: configuration.digest, N: N, n1: N, n2: g)
        
        let exp = ((resultData.mpz_u * resultData.mpz_x) + resultData.mpz_a)
        
        let tmp = (g.power(resultData.mpz_x, modulus: N) * resultData.mpz_k) % N
        
        // Add N to avoid the possible negative number.
        resultData.mpz_clientS = ((resultData.mpz_B + N - tmp) % N).power(exp, modulus: N)
        
        return resultData
    }
    
    
    /// Calculate the shared secret on the server side: S = (Av^u) ^ b
    ///
    /// - Parameter srpData: SRPData with the following parameters populated: A, v, b, B
    /// - Returns: SRPData with the computed u and serverS
    /// - Throws: SRPError if some of the required parameters are invalid.
    public func calculateServerSecret(srpData: SRPData) throws -> SRPData
    {
        try configuration.validate()
        let N = configuration.mpz_N
        
        var resultData = srpData
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.mpz_B % N) > SRPMpzT(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.mpz_b > SRPMpzT(0) else { throw SRPError.invalidServerPrivateValue }
        guard resultData.mpz_v > SRPMpzT(0) else { throw SRPError.invalidVerifier }
        
        resultData.mpz_u = hashPaddedPair(digest: configuration.digest, N: N, n1: resultData.mpz_A, n2: resultData.mpz_B)
        
        // S = (Av^u) ^ b
        resultData.mpz_serverS = ((resultData.mpz_A * resultData.mpz_v.power(resultData.mpz_u, modulus: N)) % N).power(resultData.mpz_b, modulus: N)
        
        return resultData
    }
    
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
    public func clientEvidenceMessage(srpData: SRPData) throws -> SRPData
    {
        try configuration.validate()
        let N = configuration.mpz_N
        
        var resultData = srpData
        
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.mpz_B % N) > SRPMpzT(0) else { throw SRPError.invalidServerPublicValue }
        
        if resultData.mpz_clientS == SRPMpzT(0)
        {
            resultData = try calculateClientSecret(srpData: resultData)
        }
        
        resultData.mpz_clientM = hashPaddedTriplet(digest: configuration.digest, N: N, n1: resultData.mpz_A, n2: resultData.mpz_B, n3: resultData.mpz_clientS)
        return resultData
    }
    
    
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
    public func serverEvidenceMessage(srpData: SRPData) throws -> SRPData
    {
        try configuration.validate()
        let N = SRPMpzT(configuration.modulus)
        
        var resultData = srpData
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.mpz_B % N) > SRPMpzT(0) else { throw SRPError.invalidServerPublicValue }
        if resultData.mpz_serverS == SRPMpzT(0)
        {
            resultData = try calculateServerSecret(srpData: resultData)
        }
        
        resultData.mpz_serverM = hashPaddedTriplet(digest: configuration.digest,
                                               N: N,
                                               n1: resultData.mpz_A,
                                               n2: resultData.mpz_clientM,
                                               n3: resultData.mpz_serverS)
        
        return resultData
    }
    
    
    /// Verify the client evidence message (received from the client)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: A, B, clientM, serverS
    /// - Throws: SRPError in case verification fails or when some of the required parameters are invalid.
    public func verifyClientEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let N = configuration.mpz_N
        let resultData = srpData
        guard resultData.mpz_clientM > SRPMpzT(0) else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.mpz_B % N) > SRPMpzT(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.mpz_serverS > SRPMpzT(0) else { throw SRPError.invalidServerSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest, N: N, n1: resultData.mpz_A, n2: resultData.mpz_B, n3: resultData.mpz_serverS)
        guard (M == resultData.mpz_clientM) else { throw SRPError.invalidClientEvidenceMessage }
    }
    
    
    /// Verify the server evidence message (received from the server)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: serverM, clientM, A, clientS
    /// - Throws: SRPError if verification fails or if some of the input parameters is invalid.
    public func verifyServerEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let N = configuration.mpz_N
        let resultData = srpData
        guard resultData.mpz_serverM > SRPMpzT(0) else { throw SRPError.invalidServerEvidenceMessage }
        guard resultData.mpz_clientM > SRPMpzT(0) else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.mpz_A % N) > SRPMpzT(0) else { throw SRPError.invalidClientPublicValue }
        guard resultData.mpz_clientS > SRPMpzT(0) else { throw SRPError.invalidClientSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest,
                                  N: N,
                                  n1: resultData.mpz_A,
                                  n2: resultData.mpz_clientM,
                                  n3: resultData.mpz_clientS)
        guard (M == resultData.mpz_serverM) else { throw SRPError.invalidServerEvidenceMessage }
    }
    
    
    /// Calculate the shared key (client side) in the standard way: sharedKey = H(clientS)
    ///
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateClientSharedKey(srpData: SRPData) throws -> Data
    {
        try configuration.validate()
        let resultData = srpData
        guard resultData.mpz_clientS > SRPMpzT(0) else { throw SRPError.invalidClientSharedSecret }
        let padLength = (configuration.mpz_N.width + 7) / 8
        let paddedS = pad(resultData.mpz_clientS.serialize(), to: padLength)
        let hash = configuration.digest(paddedS)
        
        return hash
    }
    
    /// Calculate the shared key (server side) in the standard way: sharedKey = H(serverS)
    ///
    /// - Parameter srpData: SRPData with serverS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateServerSharedKey(srpData: SRPData) throws -> Data
    {
        try configuration.validate()
        let resultData = srpData
        guard resultData.mpz_serverS > SRPMpzT(0) else { throw SRPError.invalidServerSharedSecret }
        let padLength = (configuration.mpz_N.width + 7) / 8
        let paddedS = pad(resultData.mpz_clientS.serialize(), to: padLength)
        let hash = configuration.digest(paddedS)
        
        return hash
    }
    
    /// Calculate the shared key (client side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateClientSharedKey(srpData: SRPData, salt: Data) throws -> Data
    {
        try configuration.validate()
        let resultData = srpData
        return configuration.hmac(salt, resultData.mpz_clientS.serialize())
    }
    
    /// Calculate the shared key (server side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateServerSharedKey(srpData: SRPData, salt: Data) throws -> Data
    {
        try configuration.validate()
        let resultData = srpData
        return configuration.hmac(salt, resultData.mpz_serverS.serialize())
    }
    
    
    /// Helper method to concatenate, pad, and hash two values.
    ///
    /// - Parameters:
    ///   - digest: The hash function to be used.
    ///   - N: Modulus; values are padded to the byte size of the modulus
    ///   - n1: First value
    ///   - n2: Second value
    /// - Returns: Result of hashing.
    internal func hashPaddedPair(digest: DigestFunc, N: SRPMpzT, n1: SRPMpzT, n2: SRPMpzT) -> SRPMpzT
    {
        let padLength = (N.width + 7) / 8
        
        let paddedN1 = pad(n1.serialize(), to: padLength)
        let paddedN2 = pad(n2.serialize(), to: padLength)
        var dataToHash = Data(capacity: paddedN1.count + paddedN2.count)
        dataToHash.append(paddedN1)
        dataToHash.append(paddedN2)
        
        let hash = digest(dataToHash)
        
        return SRPMpzT(hash) % N
    }
    
    
    /// Helper method to concatenate, pad, and hash three values.
    ///
    /// - Parameters:
    ///   - digest: The hash function to be used.
    ///   - N: Modulus; values are padded to the byte size of the modulus.
    ///   - n1: First value
    ///   - n2: Second value
    ///   - n3: Third value
    /// - Returns: Result of hashing.
    internal func hashPaddedTriplet(digest: DigestFunc, N: SRPMpzT, n1: SRPMpzT, n2: SRPMpzT, n3: SRPMpzT) -> SRPMpzT
    {
        let padLength = (N.width + 7) / 8
        
        let paddedN1 = pad(n1.serialize(), to: padLength)
        let paddedN2 = pad(n2.serialize(), to: padLength)
        let paddedN3 = pad(n3.serialize(), to: padLength)
        var dataToHash = Data(capacity: paddedN1.count + paddedN2.count + paddedN3.count)
        dataToHash.append(paddedN1)
        dataToHash.append(paddedN2)
        dataToHash.append(paddedN3)
        let hash = digest(dataToHash)
        
        return SRPMpzT(hash) % N
    }
    
    
    /// Pad the given data with zeroes to the given byte size
    ///
    /// - Parameters:
    ///   - data: Data to pad
    ///   - length: Desired byte length
    /// - Returns: Result of the padding.
    internal func pad(_ data: Data, to length: Int) -> Data
    {
        if data.count >= length
        {
            return data
        }
        
        var padded = Data(count: length - data.count)
        padded.append(data)
        return padded
    }
    
    
    /// Calculate the SRP parameter x the BouncyCastle way: x = H(s | H(I | ":" | p))
    /// | stands for concatenation
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: password
    /// - Returns: SRP value x calculated as x = H(s | H(I | ":" | p)) (where H is the configured hash function)
    internal func x(s: Data, I: Data,  p: Data) -> SRPMpzT
    {
        var identityData = Data(capacity: I.count + 1 + p.count)
        
        identityData.append(I)
        identityData.append(":".data(using: .utf8)!)
        identityData.append(p)
        
        let identityHash = configuration.digest(identityData)
        
        var xData = Data(capacity: s.count + identityHash.count)
        
        xData.append(s)
        xData.append(identityHash)
        
        let xHash = configuration.digest(xData)
        return SRPMpzT(xHash) % SRPMpzT(configuration.modulus)
    }
}

