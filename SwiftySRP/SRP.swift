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

public typealias DigestFunc = (Data) -> Data
public typealias PrivateValueFunc = (BigUInt) -> BigUInt

public struct SRP
{
    /// A large safe prime per SRP spec.
    let N: BigUInt
    
    /// A generator modulo N
    let g: BigUInt
    
    /// Hash function to be used.
    let digest: DigestFunc
    
    /// Function to calculate parameter a (per SRP spec abouve)
    private let a: PrivateValueFunc
    
    init(N: BigUInt,
         g: BigUInt,
         digest: @escaping DigestFunc = SRP.sha256DigestFunc,
         a: @escaping PrivateValueFunc = SRP.generatePrivateValue)
    {
        self.N = N
        self.g = g
        self.digest = digest
        self.a = a
    }
    
    /// SHA256 hash function
    public static let sha256DigestFunc: DigestFunc = { (data: Data) in
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(Array<UInt8>(data), CC_LONG(data.count), &hash)
        return Data(hash)
    }
    
    /// SHA512 hash function
    public static let sha512DigestFunc: DigestFunc = { (data: Data) in
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        CC_SHA512(Array<UInt8>(data), CC_LONG(data.count), &hash)
        return Data(hash)
    }

    public static func generatePrivateValue(N: BigUInt) -> BigUInt
    {
        let minBits = N.width / 2
        var random = BigUInt.randomIntegerLessThan(N)
        while (random.width < minBits)
        {
            random = BigUInt.randomIntegerLessThan(N)
        }
        
        return random
    }

    
    // TODO: Handle errors.
    public func generateClientCredentials(s: Data, I: Data, p: Data) -> (x: BigUInt, a: BigUInt, A: BigUInt)
    {
        let value_x = bouncyCastle_x(s: s, I: I, p: p)
        let value_a = a(self.N)
        let value_A = A(N: self.N, g: self.g)
        
        return (value_x, value_a, value_A)
    }
    
    public func calculateSecret(A: BigUInt, x: BigUInt, serverB: BigUInt) throws -> BigUInt
    {
        let value_B = try validatePublicValue(N: self.N, val: serverB)
        let value_u = hashPaddedPair(digest: self.digest, N: N, n1: A, n2: value_B)
        
        let k = calculate_k()
        
        // S = (B - kg^x) ^ (a + ux)
        
        let exp = (((value_u * x) % self.N) + A) % self.N
        let tmp = (self.g.power(x, modulus: self.N) * k) % self.N
        
        // Will subtraction always be positive here?
        // Apparently, yes: https://groups.google.com/forum/#!topic/clipperz/5H-tKD-l9VU
        
        let S = ((value_B - tmp) % self.N).power(exp, modulus: self.N)
        
        return S
    }

    public func calculate_k() -> BigUInt
    {
        // k = H(N, g)
        return hashPaddedPair(digest: self.digest, N: self.N, n1: self.N, n2: self.g)
    }
    
    private func hashPaddedPair(digest: DigestFunc, N: BigUInt, n1: BigUInt, n2: BigUInt) -> BigUInt
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
    
    private func validatePublicValue(N: BigUInt, val: BigUInt) throws -> BigUInt
    {
        let checkedVal = val % N
        if checkedVal == 0
        {
            // TODO: Throw error.
        }
        return checkedVal
    }
    
    private func pad(_ data: Data, to length: Int) -> Data
    {
        if data.count >= length
        {
            return data
        }
        
        var padded = Data(count: length - data.count)
        padded.append(data)
        return padded
    }
    
    
    /// Calculate the value x the BouncyCastle way: x = H(s | H(I | ":" | p))
    /// | stands for concatenation
    /// - Parameters:
    ///   - s: SRP salt
    ///   - I: User name
    ///   - p: password
    /// - Returns: SRP value x calculated as x = H(s | H(I | ":" | p)) (where H is the configured hash function)
    func bouncyCastle_x(s: Data, I: Data,  p: Data) -> BigUInt
    {
        var identityData = Data(capacity: I.count + 1 + p.count)
        
        identityData.append(I)
        identityData.append(":".data(using: .utf8)!)
        identityData.append(p)
        
        let identityHash = digest(identityData)
        
        var xData = Data(capacity: s.count + identityHash.count)
        
        xData.append(s)
        xData.append(identityHash)
        
        let xHash = digest(xData)
        let x = BigUInt(xHash) % N
        
        return x
    }
    
    internal func A(N: BigUInt, g: BigUInt) ->BigUInt
    {
        // A = g^a
        return g.power(a(N), modulus: N)
    }
    
    
    
}
