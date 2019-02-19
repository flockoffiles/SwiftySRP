//
//  SRPGenericImpl.swift
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

/// Implementation of the SRP protocol. Although it's primarily intended to be used on the client side, it includes the server side methods
/// as well (for testing purposes).
public struct SRPGenericImpl<BigIntType: SRPBigIntProtocol>: SRPProtocol
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
        
        let value_x: BigIntType = x(s: s, I: I, p: p)
        let value_a: BigIntType = BigIntType(configuration.clientPrivateValue())
        
        // A = g^a
        let value_A = BigIntType(configuration.generator).power(value_a, modulus: BigIntType(configuration.modulus))
        
        return SRPDataGenericImpl<BigIntType>(x: value_x, a: value_a, A: value_A)
    }
    
    /// Generate client credentials (parameters x, a, and A) from the SRP salt, user name (I), and password (p)
    /// This version accepts wrapped parameters (more secure).
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRP data with parameters x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    public func generateClientCredentials(s: FFDataWrapper, I: FFDataWrapper, p: FFDataWrapper) throws -> SRPData
    {
        // TODO: There may be more stringent requirements about salt.
        try configuration.validate()
        guard !s.isEmpty else { throw SRPError.invalidSalt }
        guard !I.isEmpty else { throw SRPError.invalidUserName }
        guard !p.isEmpty else { throw SRPError.invalidPassword }

        let c = self.configuration
        
        let value_x: BigIntType = s.mapData { decoded_s in
            return I.mapData { decoded_I in
                return p.mapData { decoded_p in
                    return self.x(s: decoded_s, I: decoded_I, p: decoded_p)
                }
            }
        }
        
        let value_a: BigIntType = BigIntType(configuration.clientPrivateValue())
        // A = g^a
        let value_A = BigIntType(c.generator).power(value_a, modulus: BigIntType(c.modulus))
        return SRPDataGenericImpl<BigIntType>(x: value_x, a: value_a, A: value_A)
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
        let N = BigIntType(configuration.modulus)
        let g = BigIntType(configuration.generator)
        let v:BigIntType = BigIntType(verifier)
        let k:BigIntType = hashPaddedPair(digest: configuration.digest, N: N, n1: N, n2: BigIntType(configuration.generator))
        let b:BigIntType = BigIntType(configuration.serverPrivateValue())
        
        // B = kv + g^b
        let B = (((k * v) % N) + g.power(b, modulus: N)) % N
        
        return SRPDataGenericImpl<BigIntType>(v:v, k:k, b:b, B:B)
    }

    /// Generate the server side SRP parameters. This method normally will NOT be used by the client.
    /// It's included here for testing purposes.
    /// This version uses a wrapped verifier (more secure).
    /// - Parameter verifier: SRP verifier received from the client.
    /// - Returns: SRP data with parameters v, k, b, and B populated.
    /// - Throws: SRPError if the verifier or configuration is invalid.
    public func generateServerCredentials(verifier: FFDataWrapper) throws -> SRPData
    {
        guard !verifier.isEmpty else { throw SRPError.invalidVerifier }
        try configuration.validate()
        let N = BigIntType(configuration.modulus)
        let g = BigIntType(configuration.generator)
        let v:BigIntType = BigIntType(verifier)
        let k:BigIntType = hashPaddedPair(digest: configuration.digest, N: N, n1: N, n2: BigIntType(configuration.generator))
        let b:BigIntType = BigIntType(configuration.serverPrivateValue())
        
        // B = kv + g^b
        let B = (((k * v) % N) + g.power(b, modulus: N)) % N
        
        return SRPDataGenericImpl<BigIntType>(v:v, k:k, b:b, B:B)
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
        let g = BigIntType(configuration.generator)
        let N = BigIntType(configuration.modulus)
        let bigIntV = g.power(srpData.bigInt_x(), modulus:N)
        srpData.setBigInt_v(bigIntV)
        
        return srpData
    }

    /// Compute the verifier and client credentials.
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRPData with parameters v, x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    public func verifier(s: FFDataWrapper, I: FFDataWrapper,  p: FFDataWrapper) throws -> SRPData
    {
        // let valueX = x(s:s, I:I, p:p)
        var srpData = try generateClientCredentials(s: s, I: I, p: p)
        let g = BigIntType(configuration.generator)
        let N = BigIntType(configuration.modulus)
        let bigIntV = g.power(srpData.bigInt_x(), modulus:N)
        srpData.setBigInt_v(bigIntV)
        
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
        let N: BigIntType = configuration.bigInt_N()
        let g: BigIntType = configuration.bigInt_g()
        var resultData = srpData
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.bigInt_B() % N) > BigIntType(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.bigInt_a() > BigIntType(0) else { throw SRPError.invalidClientPrivateValue }
        guard resultData.bigInt_x() > BigIntType(0) else { throw SRPError.invalidPasswordHash }
        
        let bigIntU = hashPaddedPair(digest: configuration.digest, N: N, n1: resultData.bigInt_A(), n2: resultData.bigInt_B())
        resultData.setBigInt_u(bigIntU)
        resultData.setBigInt_k(hashPaddedPair(digest: configuration.digest, N: N, n1: N, n2: g))
        
        let exp: BigIntType = ((resultData.bigInt_u() * resultData.bigInt_x()) + resultData.bigInt_a())
        
        let tmp1: BigIntType = (g.power(resultData.bigInt_x(), modulus: N) * resultData.bigInt_k()) % N
        let tmp2: BigIntType = (resultData.bigInt_B() + N - tmp1) % N
        // Add N to avoid the possible negative number.
        let tmp3: BigIntType = tmp2.power(exp, modulus: N)
        resultData.setBigInt_clientS(tmp3)
        
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
        let N: BigIntType = configuration.bigInt_N()
        
        var resultData = srpData
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.bigInt_B() % N) > BigIntType(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.bigInt_b() > BigIntType(0) else { throw SRPError.invalidServerPrivateValue }
        guard resultData.bigInt_v() > BigIntType(0) else { throw SRPError.invalidVerifier }
        
        let bigIntU = hashPaddedPair(digest: configuration.digest, N: N, n1: resultData.bigInt_A(), n2: resultData.bigInt_B())
        resultData.setBigInt_u(bigIntU)
        
        // S = (Av^u) ^ b
        let tmp: BigIntType = resultData.bigInt_A() * (resultData.bigInt_v() as BigIntType).power(resultData.bigInt_u(), modulus: N)
        let bigIntServerS = (tmp % N).power(resultData.bigInt_b(), modulus: N)
        resultData.setBigInt_serverS(bigIntServerS)
        
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
        let N: BigIntType = configuration.bigInt_N()
        
        var resultData = srpData
        
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.bigInt_B() % N) > BigIntType(0) else { throw SRPError.invalidServerPublicValue }
        
        if resultData.bigInt_clientS() == BigIntType(0)
        {
            resultData = try calculateClientSecret(srpData: resultData)
        }
        
        let bigIntClientM = hashPaddedTriplet(digest: configuration.digest,
                                              N: N, n1: resultData.bigInt_A(),
                                              n2: resultData.bigInt_B(),
                                              n3: resultData.bigInt_clientS())
        resultData.setBigInt_clientM(bigIntClientM)
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
        let N: BigIntType = BigIntType(configuration.modulus)
        
        var resultData = srpData
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.bigInt_B() % N) > BigIntType(0) else { throw SRPError.invalidServerPublicValue }
        if resultData.bigInt_serverS() == BigIntType(0)
        {
            resultData = try calculateServerSecret(srpData: resultData)
        }
        
        let bigIntServerM = hashPaddedTriplet(digest: configuration.digest,
                                              N: N,
                                              n1: resultData.bigInt_A(),
                                              n2: resultData.bigInt_clientM(),
                                              n3: resultData.bigInt_serverS())
        resultData.setBigInt_serverM(bigIntServerM)
        
        return resultData
    }
    
    
    /// Verify the client evidence message (received from the client)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: A, B, clientM, serverS
    /// - Throws: SRPError in case verification fails or when some of the required parameters are invalid.
    public func verifyClientEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let N: BigIntType = configuration.bigInt_N()
        let resultData = srpData
        guard resultData.bigInt_clientM() > BigIntType(0) else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard (resultData.bigInt_B() % N) > BigIntType(0) else { throw SRPError.invalidServerPublicValue }
        guard resultData.bigInt_serverS() > BigIntType(0) else { throw SRPError.invalidServerSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest,
                                  N: N,
                                  n1: resultData.bigInt_A(),
                                  n2: resultData.bigInt_B(),
                                  n3: resultData.bigInt_serverS())
        guard (M == resultData.bigInt_clientM()) else { throw SRPError.invalidClientEvidenceMessage }
    }
    
    
    /// Verify the server evidence message (received from the server)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: serverM, clientM, A, clientS
    /// - Throws: SRPError if verification fails or if some of the input parameters is invalid.
    public func verifyServerEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let N: BigIntType = configuration.bigInt_N()
        let resultData = srpData
        guard resultData.bigInt_serverM() > BigIntType(0) else { throw SRPError.invalidServerEvidenceMessage }
        guard resultData.bigInt_clientM() > BigIntType(0) else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.bigInt_A() % N) > BigIntType(0) else { throw SRPError.invalidClientPublicValue }
        guard resultData.bigInt_clientS() > BigIntType(0) else { throw SRPError.invalidClientSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest,
                                  N: N,
                                  n1: resultData.bigInt_A(),
                                  n2: resultData.bigInt_clientM(),
                                  n3: resultData.bigInt_clientS())
        guard (M == resultData.bigInt_serverM()) else { throw SRPError.invalidServerEvidenceMessage }
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
        let N: BigIntType = configuration.bigInt_N()
        guard resultData.bigInt_clientS() > BigIntType(0) else { throw SRPError.invalidClientSharedSecret }
        let padLength = (N.bitWidth + 7) / 8
        let paddedS = pad((resultData.bigInt_clientS() as BigIntType).serialize(), to: padLength)
        let hash = configuration.digest(paddedS)
        
        return hash
    }

    /// Calculate the shared key (client side) in the standard way: sharedKey = H(clientS)
    ///
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateClientSharedKey(srpData: SRPData) throws -> FFDataWrapper
    {
        try configuration.validate()
        let resultData = srpData
        let N: BigIntType = configuration.bigInt_N()
        guard resultData.bigInt_clientS() > BigIntType(0) else { throw SRPError.invalidClientSharedSecret }
        let padLength = (N.bitWidth + 7) / 8
        let paddedS = pad((resultData.bigInt_clientS() as BigIntType).serialize(), to: padLength)
        var hash = configuration.digest(paddedS)
        defer { FFDataWrapper.wipe(&hash) }
        return FFDataWrapper(data: hash)
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
        guard resultData.bigInt_serverS() > BigIntType(0) else { throw SRPError.invalidServerSharedSecret }
        let N: BigIntType = configuration.bigInt_N()
        let padLength: Int = (N.bitWidth + 7) / 8
        let paddedS = pad((resultData.bigInt_serverS() as BigIntType).serialize(), to: padLength)
        let hash = configuration.digest(paddedS)
        
        return hash
    }
    
    /// Calculate the shared key (server side) in the standard way: sharedKey = H(serverS)
    /// This version returns a wrapped version (more secure).
    ///
    /// - Parameter srpData: SRPData with serverS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateServerSharedKey(srpData: SRPData) throws -> FFDataWrapper
    {
        try configuration.validate()
        let resultData = srpData
        guard resultData.bigInt_serverS() > BigIntType(0) else { throw SRPError.invalidServerSharedSecret }
        let N: BigIntType = configuration.bigInt_N()
        let padLength: Int = (N.bitWidth + 7) / 8
        var paddedS: Data = pad((resultData.bigInt_serverS() as BigIntType).serialize(), to: padLength)
        defer { FFDataWrapper.wipe(&paddedS) }
        var hash: Data = configuration.digest(paddedS)
        defer { FFDataWrapper.wipe(&hash) }
        
        return FFDataWrapper(data: hash)
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
        return configuration.hmac(salt, (resultData.bigInt_clientS() as BigIntType).serialize())
    }
    
    /// Calculate the shared key (client side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// This version returns a wrapped version (more secure).
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateClientSharedKey(srpData: SRPData, salt: FFDataWrapper) throws -> FFDataWrapper
    {
        try configuration.validate()
        let resultData = srpData
        
        return salt.mapData { decodedSalt in
            var sharedKeyData = configuration.hmac(decodedSalt, (resultData.bigInt_clientS() as BigIntType).serialize())
            defer { FFDataWrapper.wipe(&sharedKeyData) }
            return FFDataWrapper(data: sharedKeyData)
        }
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
        return configuration.hmac(salt, (resultData.bigInt_serverS() as BigIntType).serialize())
    }
    
    /// Calculate the shared key (server side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// This version returns a wrapped version (more secure).
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    public func calculateServerSharedKey(srpData: SRPData, salt: FFDataWrapper) throws -> FFDataWrapper
    {
        try configuration.validate()
        let resultData = srpData
        
        return salt.mapData { decodedSalt in
            var sharedKeyData = configuration.hmac(decodedSalt, (resultData.bigInt_serverS() as BigIntType).serialize())
            defer { FFDataWrapper.wipe(&sharedKeyData) }
            return FFDataWrapper(data: sharedKeyData)
        }
    }
    
    /// Helper method to concatenate, pad, and hash two values.
    ///
    /// - Parameters:
    ///   - digest: The hash function to be used.
    ///   - N: Modulus; values are padded to the byte size of the modulus
    ///   - n1: First value
    ///   - n2: Second value
    /// - Returns: Result of hashing.
    internal func hashPaddedPair(digest: DigestFunc, N: BigIntType, n1: BigIntType, n2: BigIntType) -> BigIntType
    {
        let padLength = (N.bitWidth + 7) / 8
        
        let paddedN1 = pad(n1.serialize(), to: padLength)
        let paddedN2 = pad(n2.serialize(), to: padLength)
        var dataToHash = Data(capacity: paddedN1.count + paddedN2.count)
        dataToHash.append(paddedN1)
        dataToHash.append(paddedN2)
        
        let hash = digest(dataToHash)
        
        return BigIntType(hash) % N
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
    internal func hashPaddedTriplet(digest: DigestFunc, N: BigIntType, n1: BigIntType, n2: BigIntType, n3: BigIntType) -> BigIntType
    {
        let padLength = (N.bitWidth + 7) / 8
        
        let paddedN1 = pad(n1.serialize(), to: padLength)
        let paddedN2 = pad(n2.serialize(), to: padLength)
        let paddedN3 = pad(n3.serialize(), to: padLength)
        var dataToHash = Data(capacity: paddedN1.count + paddedN2.count + paddedN3.count)
        dataToHash.append(paddedN1)
        dataToHash.append(paddedN2)
        dataToHash.append(paddedN3)
        let hash = digest(dataToHash)
        
        return BigIntType(hash) % N
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
    internal func x(s: Data, I: Data,  p: Data) -> BigIntType
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
        return BigIntType(xHash) % BigIntType(configuration.modulus)
    }
}

