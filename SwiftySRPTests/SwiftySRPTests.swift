//
//  SwiftySRPTests.swift
//  SwiftySRPTests
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

import XCTest
@testable import SwiftySRP
import FFDataWrapper

let N_asString = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
    + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
    + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
    + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
    + "FD5138FE8376435B9FC61D2FC0EB06E3"

let g_asString = "02"

/// Tests for SRP functions.
/// Based on similar tests in BouncyCastle, but uses different hash functions (SHA256 and SHA512).
/// Expected values for the tests were generated with BouncyCastle (which is assumed to be correct).
class SwiftySRPTests: XCTestCase
{
    /// For test purposes we don't generate a randomly in certain cases.
    let fixedString_a_256 = "D2BC7017556329B81DCE85E939ED7AD070F65B4D10DDD765A50BB1D5B4C00DB75598CB787884E0987572D9FCA5B4537677DF459BA009D971F03E21E48A6EFB6B84CFD340E0419EF039778C2F6EC5057BF2F7D4F62E7758791ADB75AF48F70F8709A824E59BEEFAEC5743B06E1F5D59C36054AB0D69C8D0EC606FA8030F10C652"

    /// For test purposes we don't generate a randomly in certain cases.
    let fixedString_a_512 = "6AB27A237F596DA7CE9DAE15FF6CADC1B2089F5C5A21CB322D7EE7A7F01F534D29018D7E29E119BBD5F453F17543955F634E7D7A8428C6E9240793A388B72AB7FDF63787B28BB5A289FEE7132388F5C34167C3DD911C423646375C0836CA58456F34A544B1DD45087C8D3DDD87EB0D8BEFB339434EFA5CF46A4586B6A6E262E8"
    
    /// For test purposes we don't generate b randomly in certain cases.
    let fixedString_b_256 = "3E61561CBDDD1260D8B755DAD81887AA806A7F3828ED7F732F8614E4369105A9206D10E87E50DB80C6BEF5D72D9F2C92152BFEDCF8E2C2C1D89DB453681EF4E0134D0EF9F6A2A43537BFE642948C8CA5BFE80A80BC3229DD63A179B6D23BF3C991965D2B92AC8CF46A41199F3D3B582F72CE3D4D8FDAAD71F70DD0350611409C"
    
    /// For test purposes we don't generate b randomly in certain cases.
    let fixedString_b_512 = "89B5B98F37337E0806DA6805E085DFA62F4AF2F60C0131C13676CD18FB1DD3D71D2C3C4F92921644B91B87A2D1E1E34359903771EA5D7680AD4CC7B29A54D03655F5C6E8A2975CA7D5B4F579C55F572BF5A5D4D59DC5650AB7E2CE8DE8DCB847BF5F3F5DA581EBBC1097C88E91C14D546C0B3E5071FEEA05E6D838EB2BFCE761"
    
    let expectedString_A_256 = "67945EDA6F2843D4619740F35387015D86CA0893BB204952BEB65E90B90CA93BADED1F450CEDD699C2A3D58E2203D17BBEF02B68484E43C31BF5A62B616EA516C94366E2009F2C0202E52B26F01BBC16BCB912DEC4FE3E42DAD9A853616B9373125C2C7EC3BD5FED929FF3BAA84C8F4AB0F1B081B7FC799BCFE5F8BDB707EEEB"

    let expectedString_A_512 = "D43DA6788AD71005BF4BF32A9A8E960424FDBB0940D92D4CD00DC0C9AB3D9D52395B20E3CCB9B14BA1343AEC5D5C99D41D047C4E6E3F2B335E953559A0C327770DD57BF88F91B207A5B55143122BA7CC43CEF97917D52AC366976D28F7D4AD9BDF31867474E09235549680166D3FC46B5BD351F71CA722F0A140A3B6F3CB8F0F"

    let expected_x_256 = "65AC38DFF8BC34AE0F259E91FBD0F4CA2FA43081C9050CEC7CAC20D015F303"
    let expectedString_x_256 = "65AC38DFF8BC34AE0F259E91FBD0F4CA2FA43081C9050CEC7CAC20D015F303"
    let expected_x_512 = "B149ECB0946B0B206D77E73D95DEB7C41BD12E86A5E2EEA3893D5416591A002FF94BFEA384DC0E1C550F7ED4D5A9D2AD1F1526F01C56B5C10577730CC4A4D709"
    let expectedString_x_512 = "B149ECB0946B0B206D77E73D95DEB7C41BD12E86A5E2EEA3893D5416591A002FF94BFEA384DC0E1C550F7ED4D5A9D2AD1F1526F01C56B5C10577730CC4A4D709"

    let expectedString_B_256 = "7695C1E721DB7A7ADA8F2091BF68F113D32F6027E28F8652D552FC898A6184580E97B4C11D0F9ECF5F7ABE23EBB33C61514C1770ABF722AE757D3E9CD5E5FC0F1C479D7F6203399F7A58483DD8C94B5802ED59720C0CA626F476FBFAFC2EE153BC1E468D0B23937267C7468A94BBADA15606870C6B1F87931294708A384231A8"
    
    let expectedString_B_512 = "5B9BCD0D994B0C3BB04EF255B9C9FC6AFB9DBA26467A6F48AB2C42D925F33EB35956EE8D508012D2CA3702657370337939D4D5836353039B253BB1ADB8FE2987149E89B7527FE8598EB1107195FBC29B67C5BD5FA7B8D2CD667A6326E7531C4B8D7E6434656C732593728DB814EBBF90BCE8A8EEA254AC79F663269BFB8CD573"
    
    let expectedStringVerifier_256 = "27E2855AC715F625981DBA238667955DB341A3BDD919868943BC049736C7804CD8E0507DFEFBF5B8573F5AAE7BAC19B257034254119AB520E1F7CF3F45D01B159016847201D14C8DC95EC34E8B26EE255BC4CB28D4F97E0DB97B65BDD196C4D2951CD84F493AFD7B34B90984357988601A3643358B81689DFD0CB0D21E21CF6E"
    
    let expectedStringVerifier_512 = "E714706A2A6C6C0478444006A15EA8625943ABDFA2C0AC9085CB174623304B71A55FD9A4114E089A05CD0E898B48294B6C842B333CE8141AFCE3FA54DD8D0ED6A950642AB0066858456219F88038D68FC4AFFCAABFEC4044BA484719ADDF2FE31AB5F02BBCAAC55B5765FB1827D9E7DE8150C5BA6C891DA9CBBE1B31F3B70B3F"

    let expectedString_cM_256 = "795532FF6473671A589F05180E26AC39FEC22C290ADD5C7BEBF6609442129FEA"
    let expectedString_sM_256 = "EC17DCA98343326653D6E5865178B7058D1757F5FA1D8341DFFD9C43CDF59F73"

    let expectedString_cM_512 = "79C9D1689A5D9721CD8AF63BE1C01D3F728FED2AD1D0DCFD5051CF729720BE6CF5C4DA7F7C135EFEBF7B2B45F2ADE4AB56B527231A2EAD0C8F23639BA578B92B"
    let expectedString_sM_512 = "B93808BAC1465E4145E2593F672469DC1CC9EE7FEF2A766CED750B5A835B2AF8CCF4E59F50091F5C72100870207F97EEB8B77D082A0CFB47852D53C5BA807712"

    
    let expectedStringSharedKey_256 = "044EB29FEAA744DC7FDCAA23F43FC39A23FA99236869D890DF5650E3D0292B5E"
    let expectedStringSharedHMacKey_256 = "154610966C4C8C760E99F2F6B380E8622472F45F27708B4F8852ABA6E9FE8FAB"
    let hmacSalt256 = data(hex:"1EB95379D1E7731FBCA727673A2441FF")

    let hmacSalt512 = data(hex:"1EB95379D1E7731DAD15DC7D7B46154D6E8EFAD6982559BFBCA727673A2441FF")
    let expectedStringSharedKey_512 = "0E27EF33DCC742838FD037EE8EDE0C9CB5F526B5417570B2B9B0A57292EC0E28AEE7E01ECB98A36F90496CDE2335BEFF4290888F006CFB202EFA010ABBDE6EAA"
    let expectedStringSharedHMacKey_512 = "AF3C3D5644484E0D6C65B19F2C43F4D9C1C11C873577B2FA3C84B3EDF2D3FA1EC9005671749A881B769B21AF21E4060721B8A2DE6B43E34268860916D976A513"

    
    let s = data(hex: "BEB25379D1A8581EB5A727673A2441EE")
    let I = "alice".data(using: .utf8)!
    let p = "password123".data(using: .utf8)!

    
    var N: Data = data(hex: N_asString)
    var g: Data = data(hex: g_asString)
    
    var emptyG: Data = data(hex: "0")
    
    override func setUp()
    {
        super.setUp()
        
        print("N = \(hexString(data: N))")
        print("g = \(hexString(data: g))")
    }
    
    override func tearDown()
    {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    /// Simple test to verify that hex strings representations are the same and can be used for comparison in other tests.
    func testStringConversion()
    {
        XCTAssertEqual(N_asString, hexString(data: N))
        XCTAssertEqual(g_asString, hexString(data: g))
    }
    
    func testCreateConfigurationErrorsIMath()
    {
        genTestCreateConfigurationErrors(forBigInt: SRPMpzT())
    }

    func genTestCreateConfigurationErrors<BigIntType: SRPBigIntProtocol>(forBigInt bigIntType: BigIntType)
    {
        var caughtException = false
        
        // Create an SRP configuration with an empty generator.
        do
        {
            let _ = try SRP.protocol(N: BigIntType(N),
                                     g: BigIntType(emptyG),
                                     digest: CryptoAlgorithm.SHA256.digestFunc(),
                                     hmac: CryptoAlgorithm.SHA256.hmacFunc())
        }
        catch let e {
            if let srpError = e as? SRPError
            {
                caughtException = true
                XCTAssertEqual(srpError, SRPError.configurationGeneratorInvalid)
            }
        }
        XCTAssertTrue(caughtException, "Expecting an exception to be caught")
    }
    
    /// This test verifies calculation of the parameter x. Please note that we use the same formula for x as BouncyCastle does:
    /// x = H(s | H(I | ":" | p))  (| means concatenation and H is a hash function; SHA256 in this case)
    func genTestGenerate_x<BigIntType: SRPBigIntProtocol>(forBigInt bigIntType: BigIntType,
                                                          expected_x: String,
                                                          digest: @escaping DigestFunc,
                                                          hmac: @escaping HMacFunc)
    {
        do {
            let srp = try SRP.protocol(N: BigIntType(N),
                                       g: BigIntType(g),
                                       digest: digest,
                                       hmac: hmac) as! SRPGenericImpl<BigIntType>
            
            let x = srp.x(s: s, I: I, p: p)
            let string_x = hexString(data: x.serialize())
            XCTAssertEqual(string_x, expected_x)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
        }
        
    }
    
    func testGenerate_x_SHA256_IMath()
    {
        genTestGenerate_x(forBigInt: SRPMpzT(), expected_x: expected_x_256, digest: CryptoAlgorithm.SHA256.digestFunc(), hmac: CryptoAlgorithm.SHA256.hmacFunc())
    }

    func testGenerate_x_SHA512_IMath()
    {
        genTestGenerate_x(forBigInt: SRPMpzT(), expected_x: expected_x_512, digest: CryptoAlgorithm.SHA512.digestFunc(), hmac: CryptoAlgorithm.SHA512.hmacFunc())
    }

    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA256 as the hashing function.
    func genTestGenerateClientCredentials<BigIntType: SRPBigIntProtocol>(forBigInt bigIntType: BigIntType,
                                          digest: @escaping DigestFunc,
                                          hmac: @escaping HMacFunc,
                                          fixedString_a: String,
                                          fixedString_b: String,
                                          expectedString_x: String,
                                          expectedString_A: String)
    {
        let srp: SRPGenericImpl<BigIntType>
        do {
            // a is fixed in this test (not generated randomly)
            let fixed_a = data(hex: fixedString_a)
            let fixed_b = data(hex: fixedString_b)
            
            srp = try SRP.protocol(N: BigIntType(N),
                                   g: BigIntType(g),
                                   digest: digest,
                                   hmac: hmac,
                                   a: {  return fixed_a },
                                   b: {  return fixed_b }) as! SRPGenericImpl<BigIntType>
            
            
            let clientSRPData = (try srp.generateClientCredentials(s: s, I: I, p: p))
            
            let string_x_256 = hexString(data: clientSRPData.passwordHash)
            let string_A_256 = hexString(data: clientSRPData.clientPublicValue)
            let string_a_256 = hexString(data: clientSRPData.clientPrivateValue)
            
            XCTAssertEqual(string_x_256, expectedString_x)
            XCTAssertEqual(string_a_256, fixedString_a)
            XCTAssertEqual(string_A_256, expectedString_A)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }
        
        // Also test incorrect values
        var caughtException = false
        do {
            let _ = try srp.generateClientCredentials(s: Data(), I: I, p: p)
        } catch let e {
            if let srpError = e as? SRPError
            {
                caughtException = true
                XCTAssertEqual(srpError, SRPError.invalidSalt)
            }
        }
        XCTAssertTrue(caughtException, "Expecting an exception to be caught")
        
        caughtException = false
        do {
            let _ = try srp.generateClientCredentials(s: s, I: Data(), p: p)
        } catch let e {
            if let srpError = e as? SRPError
            {
                caughtException = true
                XCTAssertEqual(srpError, SRPError.invalidUserName)
            }
        }
        XCTAssertTrue(caughtException, "Expecting an exception to be caught")
        
        caughtException = false
        do {
            let _ = try srp.generateClientCredentials(s: s, I: I, p: Data())
        } catch let e {
            if let srpError = e as? SRPError
            {
                caughtException = true
                XCTAssertEqual(srpError, SRPError.invalidPassword)
            }
        }
        XCTAssertTrue(caughtException, "Expecting an exception to be caught")

    }
    
    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA256 as the hashing function.
    func testGenerateClientCredentials_SHA256_IMath()
    {
        genTestGenerateClientCredentials(forBigInt: SRPMpzT(),
                                         digest: CryptoAlgorithm.SHA256.digestFunc(),
                                         hmac: CryptoAlgorithm.SHA256.hmacFunc(),
                                         fixedString_a: fixedString_a_256,
                                         fixedString_b: fixedString_b_256,
                                         expectedString_x: expectedString_x_256,
                                         expectedString_A: expectedString_A_256)
    }

    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA512 as the hashing function.
    func testGenerateClientCredentials_SHA512_IMath()
    {
        genTestGenerateClientCredentials(forBigInt: SRPMpzT(),
                                         digest: CryptoAlgorithm.SHA512.digestFunc(),
                                         hmac: CryptoAlgorithm.SHA512.hmacFunc(),
                                         fixedString_a: fixedString_a_512,
                                         fixedString_b: fixedString_b_512,
                                         expectedString_x: expectedString_x_512,
                                         expectedString_A: expectedString_A_512)
    }

    func genTestVerifier<BigIntType: SRPBigIntProtocol>(forBigInt bigIntType: BigIntType,
                         digest: @escaping DigestFunc,
                         hmac: @escaping HMacFunc,
                         fixedString_a: String,
                         fixedString_b: String,
                         expectedStringVerifier: String)
    {
        // a is fixed in this test (not generated randomly)
        let fixed_a = data(hex:fixedString_a)
        let fixed_b = data(hex:fixedString_b)
        
        let srp: SRPGenericImpl<BigIntType>
        do {
            srp = try SRP.protocol(N: BigIntType(N),
                                   g: BigIntType(g),
                                   digest: digest,
                                   hmac: hmac,
                                   a: {  return fixed_a },
                                   b: {  return fixed_b }) as! SRPGenericImpl<BigIntType>
            
            let clientSRPData = try srp.verifier(s: s, I: I, p: p)
            
            let string_v = hexString(data: clientSRPData.verifier)
            
            XCTAssertEqual(string_v, expectedStringVerifier)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }
        
    }
    
    func testVerifier_SHA256_IMath()
    {
        genTestVerifier(forBigInt: SRPMpzT(),
                        digest: CryptoAlgorithm.SHA256.digestFunc(),
                        hmac: CryptoAlgorithm.SHA256.hmacFunc(),
                        fixedString_a: fixedString_a_256,
                        fixedString_b: fixedString_b_256,
                        expectedStringVerifier: expectedStringVerifier_256)
    }

    func testVerifier_SHA512_IMath()
    {
        genTestVerifier(forBigInt: SRPMpzT(),
                        digest: CryptoAlgorithm.SHA512.digestFunc(),
                        hmac: CryptoAlgorithm.SHA512.hmacFunc(),
                        fixedString_a: fixedString_a_512,
                        fixedString_b: fixedString_b_512,
                        expectedStringVerifier: expectedStringVerifier_512)
    }
    
    func genTestVerification<BigIntType: SRPBigIntProtocol>(forBigInt bigIntType: BigIntType,
                             digest: @escaping DigestFunc,
                             hmac: @escaping HMacFunc,
                             hmacSalt: Data,
                             fixedString_a: String,
                             fixedString_b: String,
                             expectedString_B: String,
                             expectedString_cM: String,
                             expectedString_sM: String,
                             expectedStringSharedKey: String,
                             expectedStringSharedHMacKey: String)
    {
        let fixed_a = data(hex:fixedString_a)
        let fixed_b = data(hex:fixedString_b)
        
        let srp: SRPProtocol
        do {
            srp = try SRP.protocol(N: BigIntType(N),
                                   g: BigIntType(g),
                                   digest: digest,
                                   hmac: hmac,
                                   a: {  return fixed_a },
                                   b: {  return fixed_b })

            // Client computes the verifier (and sends it to the server)
            var clientSRPData = try srp.verifier(s: s, I: I, p: p)
            
            // Server generates credentials by using the verifier.
            var serverSRPData = try srp.generateServerCredentials(verifier: clientSRPData.verifier)
            
            XCTAssertEqual(hexString(data: serverSRPData.serverPrivateValue), fixedString_b)
            XCTAssertEqual(hexString(data: serverSRPData.serverPublicValue), expectedString_B)
            
            // Pretend that the server has communicated its public value
            clientSRPData.serverPublicValue = serverSRPData.serverPublicValue
            
            // Client calculates the secret.
            clientSRPData = try srp.calculateClientSecret(srpData: clientSRPData)
            
            // Pretend that the client has communicated its public value
            serverSRPData.clientPublicValue = clientSRPData.clientPublicValue
            
            // Server also calculates the secret.
            serverSRPData = try srp.calculateServerSecret(srpData: serverSRPData)
            
            // Here we make sure the secrets are the same (but in real life the secret is NEVER sent over the wire).
            XCTAssertEqual(hexString(data: clientSRPData.clientSecret), hexString(data: serverSRPData.serverSecret))
            
            // Check the client evidence message.
            clientSRPData = try srp.clientEvidenceMessage(srpData: clientSRPData)
            XCTAssertEqual(hexString(data: clientSRPData.clientEvidenceMessage), expectedString_cM)
            
            // Pretend that the server has received the client evidence:
            serverSRPData.clientEvidenceMessage = clientSRPData.clientEvidenceMessage
            try srp.verifyClientEvidenceMessage(srpData: serverSRPData)
            
            serverSRPData = try! srp.serverEvidenceMessage(srpData: serverSRPData)
            XCTAssertEqual(hexString(data: serverSRPData.serverEvidenceMessage), expectedString_sM)
            
            // Pretend that the client has received the server evidence:
            clientSRPData.serverEvidenceMessage = serverSRPData.serverEvidenceMessage
            
            try srp.verifyServerEvidenceMessage(srpData: clientSRPData)
            
            let clientSharedKey: Data = try! srp.calculateClientSharedKey(srpData: clientSRPData)
            XCTAssertEqual(hexString(data: clientSharedKey), expectedStringSharedKey)
            
            let clientSharedHMacKey = try! srp.calculateClientSharedKey(srpData: clientSRPData, salt: hmacSalt)
            XCTAssertEqual(hexString(data: clientSharedHMacKey), expectedStringSharedHMacKey)
            
            
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }
        
    }
    
    /// This test verifies that the client and server way of calculating the shared secret produce the same shared secret value.
    /// (This version is for SHA256 hash function)
    func testVerification_SHA256_IMath()
    {
        genTestVerification(forBigInt: SRPMpzT(),
                            digest: CryptoAlgorithm.SHA256.digestFunc(),
                            hmac: CryptoAlgorithm.SHA256.hmacFunc(),
                            hmacSalt: hmacSalt256,
                            fixedString_a: fixedString_a_256,
                            fixedString_b: fixedString_b_256,
                            expectedString_B: expectedString_B_256,
                            expectedString_cM: expectedString_cM_256,
                            expectedString_sM: expectedString_sM_256,
                            expectedStringSharedKey: expectedStringSharedKey_256,
                            expectedStringSharedHMacKey: expectedStringSharedHMacKey_256)
    }
    
    func testVerification_SHA512_IMath()
    {
        genTestVerification(forBigInt: SRPMpzT(),
                            digest: CryptoAlgorithm.SHA512.digestFunc(),
                            hmac: CryptoAlgorithm.SHA512.hmacFunc(),
                            hmacSalt: hmacSalt512,
                            fixedString_a: fixedString_a_512,
                            fixedString_b: fixedString_b_512,
                            expectedString_B: expectedString_B_512,
                            expectedString_cM: expectedString_cM_512,
                            expectedString_sM: expectedString_sM_512,
                            expectedStringSharedKey: expectedStringSharedKey_512,
                            expectedStringSharedHMacKey: expectedStringSharedHMacKey_512)
    }
    
}
