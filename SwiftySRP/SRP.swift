//
//  SRP.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 09/02/2017.
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
import BigInt
import CommonCrypto

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
    /// Compute the verifier and client credentials.
    ///
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: Password
    /// - Returns: SRPData with parameters v, x, a, and A populated.
    /// - Throws: SRPError if input parameters or configuration are not valid.
    func verifier(s: Data, I: Data,  p: Data) throws -> SRPData

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

    /// Calculate the shared key (client side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateClientSharedKey(srpData: SRPData, salt: Data) throws -> Data

    
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

    /// Calculate the shared key (server side) by using HMAC: sharedKey = HMAC(salt, clientS)
    /// This version can be used to derive multiple shared keys from the same shared secret (by using different salts)
    /// - Parameter srpData: SRPData with clientS populated.
    /// - Returns: Shared key
    /// - Throws: SRPError if some of the required parameters is invalid.
    func calculateServerSharedKey(srpData: SRPData, salt: Data) throws -> Data

}

/// Configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
public protocol SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var modulus: Data { get }

    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var generator: Data { get }
    
    /// Hash function to be used.
    var digest: DigestFunc { get }
    
    /// Function to calculate HMAC
    var hmac: HMacFunc { get }

    /// Function to calculate parameter a (per SRP spec above)
    var a: PrivateValueFunc { get }
    
    /// Function to calculate parameter b (per SRP spec above)
    var b: PrivateValueFunc { get }
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
}

// Internal extension adding more properties
extension SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var N: BigUInt {
        get {
            return BigUInt(modulus)
        }
    }
    
    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    var g: BigUInt {
        get {
            return BigUInt(generator)
        }
        
    }

}


/// This class serves as a namespace for SRP related methods. It is not meant to be instantiated.
public class SRP
{
    
    /// Create an SRP configuration with the given parameters.
    ///
    /// - Parameters:
    ///   - N: Safe large prime per SRP spec. You can generate the prime with openssl: openssl dhparam -text 2048
    ///   - g: Group generator per SRP spec.
    ///   - digest: Hash function to be used.
    ///   - hmac: HMAC function to be used.
    /// - Throws: SRPError if configuration parameters are not valid.
    /// - Returns: The resulting SRP configuration.
    static func configuration(N: Data,
                              g: Data,
                              digest: @escaping DigestFunc = SRP.sha256DigestFunc,
                              hmac: @escaping HMacFunc = SRP.sha256HMacFunc) throws -> SRPConfiguration
    {
        let result = SRPConfigurationImpl(N: BigUInt(N),
                                          g: BigUInt(g),
                                          digest: digest,
                                          hmac: hmac,
                                          a: SRPConfigurationImpl.generatePrivateValue,
                                          b: SRPConfigurationImpl.generatePrivateValue)
        try result.validate()
        return result
    }
    
    
    /// Only for use in testing! Create an SRP configuration and provide custom closures to generate private ephemeral values 'a' and 'b'
    /// This is done to be able to use fixed values for 'a' and 'b' and make generated values predictable (and compare them with expected values).
    /// - Parameters:
    ///   - N: Safe large prime per SRP spec.
    ///   - g: Group generator per SRP spec.
    ///   - digest: Hash function to be used.
    ///   - hmac: HMAC function to be used.
    ///   - a: Custom closure to generate the private ephemeral value 'a'
    ///   - b: Custom closure to generate the private ephemeral value 'b'
    /// - Throws: SRPError if configuration parameters are not valid.
    /// - Returns: The resulting SRP configuration.
    internal static func configuration(N: Data,
                                       g: Data,
                                       digest: @escaping DigestFunc = SRP.sha256DigestFunc,
                                       hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
                                       a: @escaping PrivateValueFunc,
                                       b: @escaping PrivateValueFunc) throws -> SRPConfiguration
    {
        let result = SRPConfigurationImpl(N: BigUInt(N),
                                          g: BigUInt(g),
                                          digest: digest,
                                          hmac: hmac,
                                          a: a,
                                          b: b)
        try result.validate()
        return result
    }
    
    
    /// Create an instance of SRPProtocol with the given configuration.
    ///
    /// - Parameter configuration: SRP configuration to use.
    /// - Returns: The resulting SRP protocol implementation.
    static func srpProtocol(_ configuration: SRPConfiguration) -> SRPProtocol
    {
        return SRPImpl(configuration: configuration)
    }
    
    /// SHA256 hash function
    public static let sha256DigestFunc: DigestFunc = CryptoAlgorithm.SHA256.digestFunc()
    
    /// SHA512 hash function
    public static let sha512DigestFunc: DigestFunc = CryptoAlgorithm.SHA512.digestFunc()
    
    /// SHA256 hash function
    public static let sha256HMacFunc: HMacFunc = CryptoAlgorithm.SHA256.hmacFunc()
    
    /// SHA512 hash function
    public static let sha512HMacFunc: HMacFunc = CryptoAlgorithm.SHA512.hmacFunc()
    
    /// Generate a random private value less than the given value N and at least half the bit size of N
    ///
    /// - Parameter N: The value determining the range of the random value to generate.
    /// - Returns: Randomly generate value.
    public static func generatePrivateValue(N: Data) -> Data
    {
        return SRPConfigurationImpl.generatePrivateValue(dataN: N)
    }
}

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

/// Protocol defining SRP intermediate data.
public protocol SRPData
{
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data { get set }

    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data { get set }
    
    /// SRP Verifier.
    var verifier: Data { get set }
    
    /// Server public value 'B' (see the spec. above)
    var serverPublicValue: Data { get set }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverEvidenceMessage: Data { get set }
    
    /// Password hash (see the spec. above)
    var passwordHash: Data { get }

    /// Client private value 'a' (see the spec. above)
    var clientPrivateValue: Data { get }
    
    // u = H(A, B)
    var scrambler: Data { get set }
    
    var clientSecret: Data { get set }
    
    var serverSecret: Data { get set }
    
    var multiplier: Data { get set }
    
    var serverPrivateValue: Data { get }
    
    
}

extension SRPData
{
    // Client specific data
    
    /// Password hash (see the spec. above)
    var x: BigUInt {
        get {
            return BigUInt(passwordHash)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    var a: BigUInt {
        get {
            return BigUInt(clientPrivateValue)
        }
    }
    
    /// Client public value 'A' (see the spec. above)
    var A: BigUInt {
        get {
            return BigUInt(clientPublicValue)
        }
    }
    
    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientM: BigUInt {
        get {
            return BigUInt(clientEvidenceMessage)
        }
        set {
            clientEvidenceMessage = newValue.serialize()
        }
    }
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverM: BigUInt {
        get {
            return BigUInt(serverEvidenceMessage)
        }
        set {
            serverEvidenceMessage = newValue.serialize()
        }
    }
    
    // Common data:
    
    /// SRP Verifier.
    var v: BigUInt {
        get {
            return BigUInt(verifier)
        }
        set {
            self.verifier = newValue.serialize()
        }
    }
    
    // u = H(A, B)
    var u: BigUInt {
        get {
            return BigUInt(scrambler)
        }
        set {
            self.scrambler = newValue.serialize()
        }
    }
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var clientS: BigUInt {
        get {
            return BigUInt(clientSecret)
        }
        set {
            self.clientSecret = newValue.serialize()
        }
    }
    
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var serverS: BigUInt {
        get {
            return BigUInt(serverSecret)
        }
        set {
            self.serverSecret = newValue.serialize()
        }
    }

    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var k: BigUInt {
        get {
            return BigUInt(multiplier)
        }
        set {
            self.multiplier = newValue.serialize()
        }
    }

    
    /// Server private value 'b' (see the spec. above)
    var b: BigUInt {
        get {
            return BigUInt(serverPrivateValue)
        }
    }

    
    /// Server public value 'B' (see the spec. above)
    var B: BigUInt {
        get {
            return BigUInt(serverPublicValue)
        }
    }

}

/// SRP intermediate data (implementation)
struct SRPDataImpl: SRPData
{
    // Client specific data
    var x: BigUInt
    var a: BigUInt
    var A: BigUInt

    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientM: BigUInt
    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverM: BigUInt
    
    // Common data
    /// SRP Verifier
    var v: BigUInt
    
    /// scrambler u = H(A, B)
    var u: BigUInt
    
    /// Shared secret. Computed on the client as: S = (B - kg^x) ^ (a + ux)
    var clientS: BigUInt
    /// Shared secret. Computed on the server as: S = (Av^u) ^ b
    var serverS: BigUInt
    
    // Server specific data
    
    /// Multiplier. Computed as: k = H(N, g)
    var k: BigUInt
    
    /// Private ephemeral value 'b'
    var b: BigUInt
    
    /// Public ephemeral value 'B'
    var B: BigUInt

    
    /// Initializer to be used for client size data.
    ///
    /// - Parameters:
    ///   - x: Salted password hash (= H(s, p))
    ///   - a: Private ephemeral value 'a' (per SRP spec. above)
    ///   - A: Public ephemeral value 'A' (per SRP spec. above)
    init(x: BigUInt, a: BigUInt, A: BigUInt)
    {
        self.x = x
        self.a = a
        self.A = A
        
        self.v = 0
        self.b = 0
        self.k = 0
        self.B = 0
        self.u = 0
        self.clientS = 0
        self.serverS = 0
        self.clientM = 0
        self.serverM = 0
    }
    
    
    /// Initializer to be used for the server side data.
    ///
    /// - Parameters:
    ///   - v: SRP verifier (received from the client)
    ///   - k: Parameter 'k' (per SRP spec. above)
    ///   - b: Private ephemeral value 'b' (per SRP spec. above)
    ///   - B: Public ephemeral value 'B' (per SRP spec. above)
    init(v: BigUInt, k: BigUInt, b: BigUInt, B: BigUInt)
    {
        self.v = v
        self.k = k
        self.b = b
        self.B = B
        
        self.x = 0
        self.a = 0
        self.A = 0
        self.u = 0
        self.clientS = 0
        self.serverS = 0
        self.clientM = 0
        self.serverM = 0
    }
    
    /// Client public value 'A' (see the spec. above)
    var clientPublicValue: Data {
        get {
            return self.A.serialize()
        }
        set {
            self.A = BigUInt(newValue)
        }
    }
    
    /// Client private value 'a' (see the spec. above)
    public var clientPrivateValue: Data {
        get {
            return self.a.serialize()
        }
        set {
            self.a = BigUInt(newValue)
        }
    }
    

    /// Client evidence message, computed as: M = H( pA | pB | pS), where pA, pB, and pS - padded values of A, B, and S
    var clientEvidenceMessage: Data {
        get {
            return self.clientM.serialize()
        }
        set {
            self.clientM = BigUInt(newValue)
        }
    }
    
    /// Password hash (see the spec. above)
    public var passwordHash: Data {
        get {
            return x.serialize()
        }
        
        set {
            x = BigUInt(newValue)
        }
    }
    
    /// Scrambler u
    public var scrambler: Data {
        get {
            return u.serialize()
        }
        set {
            u = BigUInt(newValue)
        }
    }
    
    public var clientSecret: Data {
        get {
            return clientS.serialize()
        }
        set {
            clientS = BigUInt(newValue)
        }
    }

    /// SRP Verifier.
    var verifier: Data {
        get {
            return self.v.serialize()
        }
        set {
            self.v = BigUInt(newValue)
        }
    }
    
    /// Server public value 'B' (see the spec. above)
    var serverPublicValue: Data {
        get {
            return self.B.serialize()
        }
        
        set {
            self.B = BigUInt(newValue)
        }
    }
    
    public var serverPrivateValue: Data {
        get {
            return b.serialize()
        }
        set {
            self.b = BigUInt(newValue)
        }
    }
    

    
    public var serverSecret: Data {
        get {
            return serverS.serialize()
        }
        set {
            self.serverS = BigUInt(newValue)
        }
    }
    
    // k
    public var multiplier: Data {
        get {
            return k.serialize()
        }
        set {
            self.k = BigUInt(newValue)
        }
    }
    

    
    /// Server evidence message, computed as: M = H( pA | pMc | pS), where pA is the padded A value; pMc is the padded client evidence message, and pS is the padded shared secret.
    var serverEvidenceMessage: Data {
        get {
            return self.serverM.serialize()
        }
        
        set {
            self.serverM = BigUInt(newValue)
        }
    }
    

}

public typealias DigestFunc = (Data) -> Data
public typealias HMacFunc = (Data, Data) -> Data
public typealias PrivateValueFunc = (Data) -> Data

/// Convenience enum to specify a hashing algorithm
public enum CryptoAlgorithm
{
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    /// Returns the associated CCHmacAlgorithm
    var hmacAlgorithm: CCHmacAlgorithm
    {
        var result: Int = 0
        switch self
        {
            case .MD5:      result = kCCHmacAlgMD5
            case .SHA1:     result = kCCHmacAlgSHA1
            case .SHA224:   result = kCCHmacAlgSHA224
            case .SHA256:   result = kCCHmacAlgSHA256
            case .SHA384:   result = kCCHmacAlgSHA384
            case .SHA512:   result = kCCHmacAlgSHA512
        }
        
        return CCHmacAlgorithm(result)
    }
    
    /// Returns the associated digest length
    var digestLength: Int
    {
        var result: Int32 = 0
        switch self
        {
            case .MD5:      result = CC_MD5_DIGEST_LENGTH
            case .SHA1:     result = CC_SHA1_DIGEST_LENGTH
            case .SHA224:   result = CC_SHA224_DIGEST_LENGTH
            case .SHA256:   result = CC_SHA256_DIGEST_LENGTH
            case .SHA384:   result = CC_SHA384_DIGEST_LENGTH
            case .SHA512:   result = CC_SHA512_DIGEST_LENGTH
        }
        
        return Int(result)
    }
    
    /// Returns the associated DigestFunc
    public func digestFunc()-> DigestFunc
    {
        return { (data: Data) in
            var hash = [UInt8](repeating: 0, count: self.digestLength)
            switch self
            {
                case .MD5:      CC_MD5(Array<UInt8>(data), CC_LONG(data.count), &hash)
                case .SHA1:     CC_SHA1(Array<UInt8>(data), CC_LONG(data.count), &hash)
                case .SHA224:   CC_SHA224(Array<UInt8>(data), CC_LONG(data.count), &hash)
                case .SHA256:   CC_SHA256(Array<UInt8>(data), CC_LONG(data.count), &hash)
                case .SHA384:   CC_SHA384(Array<UInt8>(data), CC_LONG(data.count), &hash)
                case .SHA512:   CC_SHA512(Array<UInt8>(data), CC_LONG(data.count), &hash)
            }
            return Data(hash)
        }
    }
    
    /// Returns the associated HMacFunc
    public func hmacFunc()-> HMacFunc
    {
        return { (key, data) in
            var result: [UInt8] = Array(repeating: 0, count: self.digestLength)
            
            key.withUnsafeBytes { keyBytes in
                data.withUnsafeBytes { dataBytes in
                    CCHmac(CCHmacAlgorithm(self.hmacAlgorithm), keyBytes, key.count, dataBytes, data.count, &result)
                }
            }
            
            return Data(result)
        }
    }
}

/// Implementation of the SRP protocol. Although it's primarily intended to be used on the client side, it includes the server side methods
/// as well (for testing purposes).
public struct SRPImpl: SRPProtocol
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
    internal func generateClientCredentials(s: Data, I: Data, p: Data) throws -> SRPData
    {
        // TODO: There may be more stringent requirements about salt.
        try configuration.validate()
        guard !s.isEmpty else { throw SRPError.invalidSalt }
        guard !I.isEmpty else { throw SRPError.invalidUserName }
        guard !p.isEmpty else { throw SRPError.invalidPassword }
        
        let value_x = x(s: s, I: I, p: p)
        let value_a = BigUInt(configuration.a(configuration.modulus))

        // A = g^a
        let value_A = configuration.g.power(BigUInt(configuration.a(configuration.modulus)), modulus: configuration.N)
        
        return SRPDataImpl(x: value_x, a: value_a, A: value_A)
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
        
        let v = BigUInt(verifier)
        let k = hashPaddedPair(digest: configuration.digest, N: configuration.N, n1: configuration.N, n2: configuration.g)
        let b = BigUInt(configuration.b(configuration.modulus))
        // B = kv + g^b
        let B = (((k * v) % configuration.N) + configuration.g.power(b, modulus: configuration.N)) % configuration.N
        
        return SRPDataImpl(v:v, k:k, b:b, B:B)
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
        
        srpData.v = configuration.g.power(srpData.x, modulus:configuration.N)
        
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
        var resultData = srpData
        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard (resultData.B % configuration.N) > 0 else { throw SRPError.invalidServerPublicValue }
        guard resultData.a > 0 else { throw SRPError.invalidClientPrivateValue }
        guard resultData.x > 0 else { throw SRPError.invalidPasswordHash }
        
        resultData.u = hashPaddedPair(digest: configuration.digest, N: configuration.N, n1: resultData.A, n2: resultData.B)
        resultData.k = hashPaddedPair(digest: configuration.digest, N: configuration.N, n1: configuration.N, n2: configuration.g)

        let exp = ((resultData.u * resultData.x) + resultData.a) % configuration.N
        
        let tmp = (configuration.g.power(resultData.x, modulus: configuration.N) * resultData.k) % configuration.N
        
        // Will subtraction always be positive here?
        // Apparently, yes: https://groups.google.com/forum/#!topic/clipperz/5H-tKD-l9VU
        resultData.clientS = ((resultData.B - tmp) % configuration.N).power(exp, modulus: configuration.N)
        
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
        var resultData = srpData

        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard (resultData.B % configuration.N) > 0 else { throw SRPError.invalidServerPublicValue }
        guard resultData.b > 0 else { throw SRPError.invalidServerPrivateValue }
        guard resultData.v > 0 else { throw SRPError.invalidVerifier }
        
        resultData.u = hashPaddedPair(digest: configuration.digest, N: configuration.N, n1: resultData.A, n2: resultData.B)
        
        // S = (Av^u) ^ b
        resultData.serverS = ((resultData.A * resultData.v.power(resultData.u, modulus: configuration.N)) % configuration.N).power(resultData.b, modulus: configuration.N)
        
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
        var resultData = srpData
        
        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard (resultData.B % configuration.N) > 0 else { throw SRPError.invalidServerPublicValue }
        
        if resultData.clientS == 0
        {
            resultData = try calculateClientSecret(srpData: resultData)
        }
        
        resultData.clientM = hashPaddedTriplet(digest: configuration.digest, N: configuration.N, n1: resultData.A, n2: resultData.B, n3: resultData.clientS)
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
        var resultData = srpData
        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard (resultData.B % configuration.N) > 0 else { throw SRPError.invalidServerPublicValue }
        if resultData.serverS == 0
        {
            resultData = try calculateServerSecret(srpData: resultData)
        }
        
        resultData.serverM = hashPaddedTriplet(digest: configuration.digest,
                                               N: configuration.N,
                                               n1: resultData.A,
                                               n2: resultData.clientM,
                                               n3: resultData.serverS)
        
        return resultData
    }
    
    
    /// Verify the client evidence message (received from the client)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: A, B, clientM, serverS
    /// - Throws: SRPError in case verification fails or when some of the required parameters are invalid.
    public func verifyClientEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let resultData = srpData
        guard resultData.clientM > 0 else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard (resultData.B % configuration.N) > 0 else { throw SRPError.invalidServerPublicValue }
        guard resultData.serverS > 0 else { throw SRPError.invalidServerSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest, N: configuration.N, n1: resultData.A, n2: resultData.B, n3: resultData.serverS)
        guard (M == resultData.clientM) else { throw SRPError.invalidClientEvidenceMessage }
    }
    
    
    /// Verify the server evidence message (received from the server)
    ///
    /// - Parameter srpData: SRPData with the following fields populated: serverM, clientM, A, clientS
    /// - Throws: SRPError if verification fails or if some of the input parameters is invalid.
    public func verifyServerEvidenceMessage(srpData: SRPData) throws
    {
        try configuration.validate()
        let resultData = srpData
        guard resultData.serverM > 0 else { throw SRPError.invalidServerEvidenceMessage }
        guard resultData.clientM > 0 else { throw SRPError.invalidClientEvidenceMessage }
        guard (resultData.A % configuration.N) > 0 else { throw SRPError.invalidClientPublicValue }
        guard resultData.clientS > 0 else { throw SRPError.invalidClientSharedSecret }
        
        let M = hashPaddedTriplet(digest: configuration.digest, N: configuration.N, n1: resultData.A, n2: resultData.clientM, n3: resultData.clientS)
        guard (M == resultData.serverM) else { throw SRPError.invalidServerEvidenceMessage }
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
        guard resultData.clientS > 0 else { throw SRPError.invalidClientSharedSecret }
        let padLength = (configuration.N.width + 7) / 8
        let paddedS = pad(resultData.clientS.serialize(), to: padLength)
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
        guard resultData.serverS > 0 else { throw SRPError.invalidServerSharedSecret }
        let padLength = (configuration.N.width + 7) / 8
        let paddedS = pad(resultData.clientS.serialize(), to: padLength)
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
        return configuration.hmac(salt, resultData.clientS.serialize())
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
        return configuration.hmac(salt, resultData.serverS.serialize())
    }

    
    /// Helper method to concatenate, pad, and hash two values.
    ///
    /// - Parameters:
    ///   - digest: The hash function to be used.
    ///   - N: Modulus; values are padded to the byte size of the modulus
    ///   - n1: First value
    ///   - n2: Second value
    /// - Returns: Result of hashing.
    internal func hashPaddedPair(digest: DigestFunc, N: BigUInt, n1: BigUInt, n2: BigUInt) -> BigUInt
    {
        let padLength = (N.width + 7) / 8
        
        let paddedN1 = pad(n1.serialize(), to: padLength)
        let paddedN2 = pad(n2.serialize(), to: padLength)
        var dataToHash = Data(capacity: paddedN1.count + paddedN2.count)
        dataToHash.append(paddedN1)
        dataToHash.append(paddedN2)
        
        let hash = digest(dataToHash)
        
        return BigUInt(hash) % N
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
    internal func hashPaddedTriplet(digest: DigestFunc, N: BigUInt, n1: BigUInt, n2: BigUInt, n3: BigUInt) -> BigUInt
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
        
        return BigUInt(hash) % N
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
    internal func x(s: Data, I: Data,  p: Data) -> BigUInt
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
        let x = BigUInt(xHash) % configuration.N
        
        return x
    }
}

/// Configuration for SRP algorithms (see the spec. above for more information about the meaning of parameters).
class SRPConfigurationImpl: SRPConfiguration
{
    /// A large safe prime per SRP spec. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var modulus: Data {
        return N.serialize()
    }

    /// A generator modulo N. (Also see: https://tools.ietf.org/html/rfc5054#appendix-A)
    public var generator: Data {
        return g.serialize()
    }
    
    /// A large safe prime per SRP spec.
    let N: BigUInt
    
    /// A generator modulo N
    let g: BigUInt
    
    /// Hash function to be used.
    let digest: DigestFunc
    
    /// Function to calculate HMAC
    let hmac: HMacFunc
    
    /// Function to calculate parameter a (per SRP spec above)
    let a: PrivateValueFunc
    
    /// Function to calculate parameter b (per SRP spec above)
    let b: PrivateValueFunc
    
    init(N: BigUInt,
         g: BigUInt,
         digest: @escaping DigestFunc = SRP.sha256DigestFunc,
         hmac: @escaping HMacFunc = SRP.sha256HMacFunc,
         a: @escaping PrivateValueFunc = SRPConfigurationImpl.generatePrivateValue,
         b: @escaping PrivateValueFunc = SRPConfigurationImpl.generatePrivateValue)
    {
        self.N = N
        self.g = g
        self.digest = digest
        self.a = a
        self.b = b
        self.hmac = hmac
    }
    
    
    /// Check if configuration is valid.
    /// Currently only requires the size of the prime to be >= 256 and the g to be greater than 1.
    /// - Throws: SRPError if invalid.
    func validate() throws
    {
        guard N.width >= 256 else { throw SRPError.configurationPrimeTooShort }
        guard g > 1 else { throw SRPError.configurationGeneratorInvalid }
    }
    
    /// Generate a random private value less than the given value N and at least half the bit size of N
    ///
    /// - Parameter N: The value determining the range of the random value to generate.
    /// - Returns: Randomly generate value.
    public static func generatePrivateValue(dataN: Data) -> Data
    {
        let N = BigUInt(dataN)
        let minBits = N.width / 2
        var random = BigUInt.randomIntegerLessThan(N)
        while (random.width < minBits)
        {
            random = BigUInt.randomIntegerLessThan(N)
        }
        
        return random.serialize()
    }
}

/// Helper category to perform conversion of hex strings to data
extension UnicodeScalar
{
    var hexNibble:UInt8
    {
        let value = self.value
        if 48 <= value && value <= 57 {
            return UInt8(value - 48)
        }
        else if 65 <= value && value <= 70 {
            return UInt8(value - 55)
        }
        else if 97 <= value && value <= 102 {
            return UInt8(value - 87)
        }
        fatalError("\(self) not a legal hex nibble")
    }
}


/// Helper category to perform conversion of hex strings to data
extension Data
{
    init(hex:String)
    {
        let scalars = hex.unicodeScalars
        var bytes = Array<UInt8>(repeating: 0, count: (scalars.count + 1) >> 1)
        for (index, scalar) in scalars.enumerated()
        {
            var nibble = scalar.hexNibble
            if index & 1 == 0 {
                nibble <<= 4
            }
            bytes[index >> 1] |= nibble
        }
        self = Data(bytes: bytes)
    }
    
    func hexString() -> String
    {
        var result = String()
        result.reserveCapacity(self.count * 2)
        [UInt8](self).forEach { (aByte) in
            result += String(format: "%02X", aByte)
        }
        return result
    }
}

public extension BigUInt
{
    func hexString() -> String
    {
        return String(self, radix: 16, uppercase: true)
    }
}

/// Helper category to convert BitUInt value to a hex string.
extension BigUInt: CustomDebugStringConvertible
{
    public var debugDescription: String {
        return String(self, radix: 16, uppercase: true)
    }
}


