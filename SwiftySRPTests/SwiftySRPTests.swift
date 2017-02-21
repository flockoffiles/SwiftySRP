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
import BigInt

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

    let expectedStringM_512 = "79C9D1689A5D9721CD8AF63BE1C01D3F728FED2AD1D0DCFD5051CF729720BE6CF5C4DA7F7C135EFEBF7B2B45F2ADE4AB56B527231A2EAD0C8F23639BA578B92B"
    let expectedString_sM_512 = "B93808BAC1465E4145E2593F672469DC1CC9EE7FEF2A766CED750B5A835B2AF8CCF4E59F50091F5C72100870207F97EEB8B77D082A0CFB47852D53C5BA807712"

    
    let expectedStringSharedKey_256 = "044EB29FEAA744DC7FDCAA23F43FC39A23FA99236869D890DF5650E3D0292B5E"
    let expectedStringSharedHMacKey_256 = "154610966C4C8C760E99F2F6B380E8622472F45F27708B4F8852ABA6E9FE8FAB"
    let hmacSalt256 = Data(hex:"1EB95379D1E7731FBCA727673A2441FF")

    let hmacSalt512 = Data(hex:"1EB95379D1E7731DAD15DC7D7B46154D6E8EFAD6982559BFBCA727673A2441FF")
    let expectedStringSharedKey_512 = "0E27EF33DCC742838FD037EE8EDE0C9CB5F526B5417570B2B9B0A57292EC0E28AEE7E01ECB98A36F90496CDE2335BEFF4290888F006CFB202EFA010ABBDE6EAA"
    let expectedStringSharedHMacKey_512 = "AF3C3D5644484E0D6C65B19F2C43F4D9C1C11C873577B2FA3C84B3EDF2D3FA1EC9005671749A881B769B21AF21E4060721B8A2DE6B43E34268860916D976A513"

    
    let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
    let I = "alice".data(using: .utf8)!
    let p = "password123".data(using: .utf8)!

    
    var N: Data = BigUInt(N_asString, radix: 16)!.serialize()
    var g: Data = BigUInt(g_asString, radix: 16)!.serialize()
    
    override func setUp()
    {
        super.setUp()
        
        print("N = \(N.hexString())")
        print("g = \(g.hexString())")
    }
    
    override func tearDown()
    {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    /// Simple test to verify that hex strings representations are the same and can be used for comparison in other tests.
    func test01StringConversion()
    {
        XCTAssertEqual(N_asString, N.hexString())
        XCTAssertEqual(g_asString, g.hexString())
    }
    
    /// Simple test to verify that conversion of BigUInt to Data gives correct representation in terms of the order of bytes.
    func test02DataConversion()
    {
        let N: BigUInt = BigUInt(N_asString, radix: 16)!
        let N_data = N.serialize()
        let N_dataArray = [UInt8](N_data)
        let recoveredString = N_dataArray.reduce("") { (aResult, aCurrentValue) -> String in
            return aResult + String(format: "%02X", aCurrentValue)
        }
        XCTAssertEqual(N_asString, recoveredString)
    }
    
    func test03CreateConfigurationErrors()
    {
        var caughtException = false
        
        // Create an SRP configuration with an empty generator.
        do
        {
            let _ = try SRP.configuration(N: N, g:Data(), digest: SRP.sha256DigestFunc,
                                          hmac: SRP.sha256HMacFunc)
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
    func test04Generate_x_SHA256()
    {
        do {
            let srp256 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha256DigestFunc, hmac: SRP.sha256HMacFunc)) as! SRPImpl
            let x_256 = srp256.x(s: s, I: I, p: p)
            let string_x_256 = String(x_256, radix: 16, uppercase: true)
            XCTAssertEqual(string_x_256, expected_x_256)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
        }

    }

    /// This test verifies calculation of the parameter x. Please note that we use the same formula for x as BouncyCastle does:
    /// x = H(s | H(I | ":" | p))  (| means concatenation and H is a hash function; SHA512 in this case)
    func test04Generate_x_SHA512()
    {
        do {
            let srp512 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha512DigestFunc, hmac:SRP.sha512HMacFunc)) as! SRPImpl
            let x_512 = srp512.x(s: s, I: I, p: p)
            let string_x_512 = String(x_512, radix: 16, uppercase: true)
            XCTAssertEqual(string_x_512, expected_x_512)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
        }
    }
    
    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA256 as the hashing function.
    func test05GenerateClientCredentials_SHA256()
    {
        let srp256: SRPImpl
        do {
            // a is fixed in this test (not generated randomly)
            let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!.serialize()
            let fixed_b_256 = BigUInt(fixedString_b_256, radix: 16)!.serialize()
            
            srp256 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha256DigestFunc,
                                                           hmac: SRP.sha256HMacFunc,
                                                           a: { _ in return fixed_a_256 },
                                                           b: { _ in return fixed_b_256 })) as! SRPImpl

            
            let clientSRPData = (try srp256.generateClientCredentials(s: s, I: I, p: p))
            
            let string_x_256 = String(clientSRPData.x, radix: 16, uppercase: true)
            let string_A_256 = String(clientSRPData.A, radix: 16, uppercase: true)
            let string_a_256 = String(clientSRPData.a, radix: 16, uppercase: true)
            
            XCTAssertEqual(string_x_256, expectedString_x_256)
            XCTAssertEqual(string_a_256, fixedString_a_256)
            XCTAssertEqual(string_A_256, expectedString_A_256)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }

        // Also test incorrect values
        var caughtException = false
        do {
            let _ = try srp256.generateClientCredentials(s: Data(), I: I, p: p)
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
            let _ = try srp256.generateClientCredentials(s: s, I: Data(), p: p)
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
            let _ = try srp256.generateClientCredentials(s: s, I: I, p: Data())
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
    /// This test is for SRP using SHA512 as the hashing function.
    func test05GenerateClientCredentials_SHA512()
    {
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!.serialize()
        let fixed_b_512 = BigUInt(fixedString_b_512, radix: 16)!.serialize()
        let srp_512: SRPImpl
        
        do {
            srp_512 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha512DigestFunc, hmac:SRP.sha512HMacFunc,
                                                            a: { _ in return fixed_a_512 },
                                                            b: { _ in return fixed_b_512 })) as! SRPImpl
            
            let clientSRPData = try srp_512.generateClientCredentials(s: s, I: I, p: p)
            let string_x_512 = String(clientSRPData.x, radix: 16, uppercase: true)
            let string_A_512 = String(clientSRPData.A, radix: 16, uppercase: true)
            let string_a_512 = String(clientSRPData.a, radix: 16, uppercase: true)
            
            XCTAssertEqual(string_x_512, expectedString_x_512)
            XCTAssertEqual(string_a_512, fixedString_a_512)
            XCTAssertEqual(string_A_512, expectedString_A_512)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }
    }
    
    /// Test to verify that the SRP verifier is calculated correctly (this version is for SHA256 hash function).
    func test06Verifier_SHA256()
    {
        // a is fixed in this test (not generated randomly)
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!.serialize()
        let fixed_b_256 = BigUInt(fixedString_b_256, radix: 16)!.serialize()
        
        let srp256: SRPImpl
        do {
            srp256 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha256DigestFunc, hmac: SRP.sha256HMacFunc,
                                                           a: { _ in return fixed_a_256 },
                                                           b: { _ in return fixed_b_256 })) as! SRPImpl
            
            let clientSRPData = try srp256.verifier(s: s, I: I, p: p)

            let string_v_256 = String(clientSRPData.v, radix: 16, uppercase: true)
            
            XCTAssertEqual(string_v_256, expectedStringVerifier_256)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }

    }
    
    /// Test to verify that the SRP verifier is calculated correctly (this version is for SHA512 hash function).
    func test06Verifier_SHA512()
    {
        // a is fixed in this test (not generated randomly)
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!.serialize()
        let fixed_b_512 = BigUInt(fixedString_b_512, radix: 16)!.serialize()
        let srp512: SRPImpl
        
        do {
            srp512 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha512DigestFunc, hmac:SRP.sha512HMacFunc,
                                                             a: { _ in return fixed_a_512 },
                                                             b: { _ in return fixed_b_512 })) as! SRPImpl
            
            let clientSRPData = try srp512.verifier(s: s, I: I, p: p)
            
            let string_v_512 = String(clientSRPData.v, radix: 16, uppercase: true)
            
            XCTAssertEqual(string_v_512, expectedStringVerifier_512)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }

    }
    
    /// This test verifies that the client and server way of calculating the shared secret produce the same shared secret value.
    /// (This version is for SHA256 hash function)
    func test07Verification_SHA256()
    {
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!.serialize()
        let fixed_b_256 = BigUInt(fixedString_b_256, radix: 16)!.serialize()
        
        let srp256: SRPProtocol
        do {
            srp256 = SRP.srpProtocol(try SRP.configuration(N: N, g:g, digest: SRP.sha256DigestFunc, hmac: SRP.sha256HMacFunc,
                                                             a: { _ in return fixed_a_256 },
                                                             b: { _ in return fixed_b_256 }))
            
            // Client computes the verifier (and sends it to the server)
            var clientSRPData = try srp256.verifier(s: s, I: I, p: p)

            // Server generates credentials by using the verifier.
            var serverSRPData = try srp256.generateServerCredentials(verifier: clientSRPData.v.serialize())
            
            XCTAssertEqual(serverSRPData.b.hexString(), fixedString_b_256)
            XCTAssertEqual(serverSRPData.B.hexString(), expectedString_B_256)
            
            // Pretend that the server has communicated its public value
            clientSRPData.serverPublicValue = serverSRPData.serverPublicValue

            // Client calculates the secret.
            clientSRPData = try srp256.calculateClientSecret(srpData: clientSRPData)
            
            // Pretend that the client has communicated its public value
            serverSRPData.clientPublicValue = clientSRPData.clientPublicValue
            
            // Server also calculates the secret.
            serverSRPData = try srp256.calculateServerSecret(srpData: serverSRPData)
            
            // Here we make sure the secrets are the same (but in real life the secret is NEVER sent over the wire).
            XCTAssertEqual(clientSRPData.clientS.hexString(), serverSRPData.serverS.hexString())
            
            // Check the client evidence message.
            clientSRPData = try srp256.clientEvidenceMessage(srpData: clientSRPData)
            XCTAssertEqual(clientSRPData.clientM.hexString(), expectedString_cM_256)
            
            // Pretend that the server has received the client evidence:
            serverSRPData.clientM = clientSRPData.clientM
            try srp256.verifyClientEvidenceMessage(srpData: serverSRPData)
            
            serverSRPData = try! srp256.serverEvidenceMessage(srpData: serverSRPData)
            XCTAssertEqual(serverSRPData.serverM.hexString(), expectedString_sM_256)
            
            // Pretend that the client has received the server evidence:
            clientSRPData.serverM = serverSRPData.serverM
            
            try srp256.verifyServerEvidenceMessage(srpData: clientSRPData)
            
            let clientSharedKey_256 = try! srp256.calculateClientSharedKey(srpData: clientSRPData)
            XCTAssertEqual(clientSharedKey_256.hexString(), expectedStringSharedKey_256)

            let clientSharedHMacKey_256 = try! srp256.calculateClientSharedKey(srpData: clientSRPData, salt: hmacSalt256)
            XCTAssertEqual(clientSharedHMacKey_256.hexString(), expectedStringSharedHMacKey_256)
            
            
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }

    }
    
    /// This test verifies that the client and server way of calculating the shared secret produce the same shared secret value.
    /// (This version is for SHA512 hash function)
    func test07Verification_SHA512()
    {
        
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!.serialize()
        let fixed_b_512 = BigUInt(fixedString_b_512, radix: 16)!.serialize()
        let srp512: SRPProtocol
        
        do {
            srp512 = SRP.srpProtocol(try SRP.configuration(N: N, g:g,
                                                           digest: SRP.sha512DigestFunc,
                                                           hmac:SRP.sha512HMacFunc,
                                                             a: { _ in return fixed_a_512 },
                                                             b: { _ in return fixed_b_512 }))
            
            var clientSRPData = try srp512.verifier(s: s, I: I, p: p)
            
            var serverSRPData = try srp512.generateServerCredentials(verifier: clientSRPData.v.serialize())
            
            XCTAssertEqual(serverSRPData.b.hexString(), fixedString_b_512)
            XCTAssertEqual(serverSRPData.B.hexString(), expectedString_B_512)

            // Pretend that the server has communicated its public value
            clientSRPData.serverPublicValue = serverSRPData.serverPublicValue
            
            clientSRPData = try srp512.calculateClientSecret(srpData: clientSRPData)
            
            // Pretend that the client has communicated its public value
            serverSRPData.clientPublicValue = clientSRPData.clientPublicValue
            
            serverSRPData = try srp512.calculateServerSecret(srpData: serverSRPData)
            
            // Here we make sure the secrets are the same (but in real life the secret is NEVER sent over the wire).
            XCTAssertEqual(clientSRPData.clientS.hexString(), serverSRPData.serverS.hexString())
            
            // Check the client evidence message.
            clientSRPData = try srp512.clientEvidenceMessage(srpData: clientSRPData)
            XCTAssertEqual(clientSRPData.clientM.hexString(), expectedStringM_512)
            
            // Pretend that the server has received the client evidence:
            serverSRPData.clientM = clientSRPData.clientM
            try srp512.verifyClientEvidenceMessage(srpData: serverSRPData)

            serverSRPData = try srp512.serverEvidenceMessage(srpData: serverSRPData)
            XCTAssertEqual(serverSRPData.serverM.hexString(), expectedString_sM_512)
            
            // Pretend that the client has received the server evidence:
            clientSRPData.serverM = serverSRPData.serverM
            
            try srp512.verifyServerEvidenceMessage(srpData: clientSRPData)

            let clientSharedKey_512 = try! srp512.calculateClientSharedKey(srpData: clientSRPData)
            
            XCTAssertEqual(clientSharedKey_512.hexString(), expectedStringSharedKey_512)

            
            let sharedHMacKey_512 = try! srp512.calculateClientSharedKey(srpData: clientSRPData, salt: hmacSalt512)
            let stringSharedHMacKey_512 = sharedHMacKey_512.hexString()
            XCTAssertEqual(stringSharedHMacKey_512, expectedStringSharedHMacKey_512)
        }
        catch let e {
            XCTFail("Caught exception: \(e)")
            return
        }

    }
    
    
    
    
}
