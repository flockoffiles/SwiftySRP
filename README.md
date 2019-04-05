# SwiftySRP
This is an implementation of SRP 6a compatible with that of [BouncyCastle](http://www.docjar.org/docs/api/org/bouncycastle/crypto/agreement/srp/package-index.html).

For SRP 6a Specification, see: 

[SRP Design Specification](http://srp.stanford.edu/design.html) <br/>
[SRP RFC](https://tools.ietf.org/html/rfc5054)


## How to Install

### Cocoapods
To use with cocoapods, add the following line to your Podfile:

```
pod 'SwiftySRP', '~> 2.12'
```

### Carthage
To use with Carthage, add the following line to your Cartfile:

```
github "flockoffiles/SwiftySRP" ~> 2.12
```


## Xcode 10 vs 9.4 Support

Starting with version 2.7 SwiftySRP no longer supports building with Xcode 9 (because of the different ways the CommonCrypto library must be imported). If you still need to support XCode 9, you have to stay on version 2.6.

## How to Use

Currently the implementation is Swift-only and supports iOS9.3 and higher.

To use the SRP on the client side you need to create an SRP protocol instance, <br/> where you specify a **large safe prime number** (see below on how to generate one), a **generator**, a **hashing function**, and an **HMAC function** <br/>
(HMAC function is used as an alternative way to generate a shared session key from the shared secret; this way we can generate multiple session keys from the same shared secret by utilizing different HMAC keys).

```swift

// In this example we use the same prime that BouncyCastle tests use.
let N = data(hex: "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
    + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
    + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
    + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
    + "FD5138FE8376435B9FC61D2FC0EB06E3")

// In this example we use the same prime that BouncyCastle tests use.
let g = data(hex: "02")

// Use SHA256 as the hashing function, and HMAC-SHA256 as the HMAC function.
let srp256 = try SRP.iMath.protocol(N: N, g:g, digest: CryptoAlgorithm.SHA256.digestFunc(), hmac: CryptoAlgorithm.SHA256.hmacFunc())

```

Afterwards, you should generate the verifier and send it over to the server.
(You need to generate an SRP salt and obtain the user's name and password to generate the verifier.)


```swift
// Normally you would get this from the user:
let userName = "alice".data(using: .utf8)!
// Normally you would get this from the user:
let userPassword = "password123".data(using: .utf8)!

// Just a way to generate the salt... (implemented in a separate category)
let salt = Data.generateRandomBytes(count: 128)

// Generate the verifier
let srpData: SRPData = try srp256.verifier(s: salt, I: userName, p: password)
let verifier: Data = srpData.verifier()

// Now you must send the salt, userName, and the verifier to the server.
```

At the time of login you must first receive the salt and the public value 'B' parameters back from the server.
Then you can obtain the userName and password from the user and generate the client side evidence message:

```swift
let srp = try SRP.iMath.protocol(N: N, g:g, digest: CryptoAlgorithm.SHA256.digestFunc(), hmac: CryptoAlgorithm.SHA256.hmacFunc())

// TODO: Obtain the salt and parameter 'B' from the server.
// Also, the server can send a number of HMAC keys to generate shared session keys.
// let salt: Data = ...
// let B:Data = ...
// let hmacKey1: Data = ...

// TODO: Obtain the userName and password from the user.
// let userName: Data = ...
// let password: Data = ...

var srpData = try srp.generateClientCredentials(s:salt, I:userName, p:password)

srpData.serverPublicValue = B

srpData = try srp.clientEvidenceMessage(srpData: srpData)

// Now send the following values to the server:
// - userName
// - srpData.clientM.serialize()
// - srpData.A.serialize()

// The server will verify the client evidence and, if successful, should send back its own evidence message: serverM
srpData.serverEvidenceMessage = serverM

// Validate the server evidence message:
try srp.verifyServerEvidenceMessage(srpData: clientSRPData)

// Now derive the shared session key.
let clientSharedSessionKey: Data = try! srp.calculateClientSharedKey(srpData: clientSRPData, salt: hmacKey1)

```




### Generating Safe Primes

To generate a large safe prime, you can use, for example, openssl in the following way:

```bash
openssl dhparam -text 2048
```

This is going to take a rather long time, but in the end you get the prime printed in hex form.

Example output. You can remove the ':' delimiters and use the resulting string

```
...
Diffie-Hellman-Parameters: (2048 bit)
    prime:
        00:9c:6e:73:6c:3a:9d:9c:22:5c:ce:c9:ab:08:b0:
        fa:46:1d:d3:3b:af:39:d7:34:77:54:5a:c9:7a:99:
        76:62:bc:f4:b4:a3:1a:51:fe:c9:de:69:d1:c6:7c:
        78:a7:18:ad:cb:ae:d9:02:72:1b:a0:2d:45:77:72:
        4c:96:d2:ac:74:85:f4:3e:16:96:2d:bb:88:7d:6e:
        5f:64:bb:87:69:d2:97:0a:c5:3a:b5:b0:35:34:83:
        74:a8:dd:d0:e6:52:d2:e0:41:7d:e9:a7:6d:92:bc:
        8d:87:4c:2b:eb:68:e3:53:1d:97:e3:c2:50:82:9d:
        3a:db:ca:b6:9f:d5:d4:b5:42:6c:4d:46:c0:94:3b:
        45:1d:41:0d:c1:56:d2:56:14:04:84:b2:00:84:07:
        d5:4f:b5:11:2b:59:3c:58:c8:18:5e:c1:94:c8:2e:
        e9:82:6a:e5:11:3d:0c:96:50:56:04:ea:d3:39:e1:
        ea:e4:fc:fd:0d:c3:f7:e9:68:7f:ae:5a:e6:1c:6d:
        5a:b8:18:6f:06:68:2d:74:52:80:ae:31:04:75:a8:
        00:75:57:c6:bb:de:f7:aa:2c:76:91:36:ff:eb:5e:
        86:5e:de:95:7e:f7:86:ab:96:1a:16:56:41:5a:c6:
        63:73:3e:e1:9f:c0:85:59:4c:88:55:91:fc:4e:1e:
        62:5b
    generator: 2 (0x2)
...

```





