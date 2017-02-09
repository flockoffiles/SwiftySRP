//
//  SRP.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 09/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation
import BigInt
import CommonCrypto

// SPR Design spec: http://srp.stanford.edu/design.html
// Bouncy Castle Implementation:
// http://www.docjar.org/docs/api/org/bouncycastle/crypto/agreement/srp/package-index.html

// http://stackoverflow.com/questions/30195267/how-to-byte-reverse-nsdata-output-in-swift-the-littleendian-way
// https://github.com/anotheren/SwiftyHash/blob/master/Source/HashType.swift

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



// TODO:
//
// - Generate A

public typealias DigestFunc = (Data) -> Data

public struct SRP
{
    private let N: BigUInt
    private let g: BigUInt
    private let digest: DigestFunc
    
    public static let sha256DigestFunc: DigestFunc = { (data: Data) in
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(Array<UInt8>(data), CC_LONG(data.count), &hash)
        return Data(hash)
    }
    
    // TODO: Handle errors.
    public func generateClientCredentials(s: Data, I: Data, p: Data) -> (x: BigUInt, a: BigUInt, A: BigUInt)
    {
        let value_x = bouncyCastle_x(digest: self.digest, N: self.N, s: s, I: I, p: p)
        let value_a = a(N: self.N)
        let value_A = A(N: self.N, g: self.g)
        
        return (value_x, value_a, value_A)
    }
    
    public func calculateSecret(A: BigUInt, x: BigUInt, serverB: BigUInt) throws -> BigUInt
    {
        let value_B = try validatePublicValue(N: self.N, val: serverB)
        let value_u = hashPaddedPair(digest: self.digest, N: N, n1: A, n2: value_B)
        
        let k = hashPaddedPair(digest: self.digest, N: self.N, n1: self.N, n2: self.g)
        
        // S = (B - kg^x) ^ (a + ux)
        
        let exp = (((value_u * x) % self.N) + A) % self.N
        let tmp = (self.g.power(x, modulus: self.N) * k) % self.N
        
        // TODO: Will subtraction always succeed here?
        let S = ((value_B - tmp) % self.N).power(exp, modulus: self.N)
        
        return S
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
    
    private func bouncyCastle_x(digest: DigestFunc, N: BigUInt, s: Data, I: Data,  p: Data) -> BigUInt
    {
        var identityData = Data(capacity: I.count + 1 + p.count)
        
        identityData.append(I)
        identityData.append(":".data(using: .utf8)!)
        identityData.append(p)
        
        let identityHash = digest(identityData)
        
        var xData = Data(capacity: s.count + identityHash.count)
        
        xData.append(s)
        xData.append(identityHash)
        
        // Please check if it's big endian and reverse if necessary.
        let x = BigUInt(xData) % N
        
        return x
    }
    
    private func a(N: BigUInt) -> BigUInt
    {
        return generatePrivateValue(N: N)
    }
    
    private func A(N: BigUInt, g: BigUInt) ->BigUInt
    {
        // A = g^a
        return g.power(a(N: N), modulus: N)
    }
    
    private func generatePrivateValue(N: BigUInt) -> BigUInt
    {
        let minBits = N.width / 2
        var random = BigUInt.randomIntegerLessThan(N)
        while (random.width < minBits)
        {
            random = BigUInt.randomIntegerLessThan(N)
        }
        
        return random
    }
    
    
}
