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

let g_asString = "2"

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
    
    let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
    let I = "alice".data(using: .utf8)!
    let p = "password123".data(using: .utf8)!

    
    var N: BigUInt = BigUInt(N_asString, radix: 16)!
    var g: BigUInt = BigUInt(g_asString, radix: 16)!

    override func setUp()
    {
        super.setUp()
        
        print("N = \(String(N, radix: 16, uppercase: true))")
        print("g = \(String(g, radix: 16, uppercase: true))")
    }
    
    override func tearDown()
    {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    /// Simple test to verify that hex strings representations are the same and can be used for comparison in other tests.
    func test01StringConversion()
    {
        XCTAssertEqual(N_asString, String(N, radix: 16, uppercase: true))
        XCTAssertEqual(g_asString, String(g, radix: 16, uppercase: true))
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
    
    /// This test verifies calculation of the parameter k = H(N, g) for H = SHA256
    func test03Generate_k_SHA256()
    {
        // Generated with BouncyCastle: SRP6Util.calculateK(new SHA256Digest(), N, g).toString(16).toUpperCase()
        let expectedString_k256 = "1A1A4C140CDE70AE360C1EC33A33155B1022DF951732A476A862EB3AB8206A5C"
        
        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc)
        
        let k256 = srp256.calculate_k()
        
        let string_k_256 = String(k256, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_k_256, expectedString_k256)
    }
    
    /// This test verifies calculation of the parameter k = H(N, g) for H = SHA512
    func test03Generate_k_SHA512()
    {
        // Generated with BouncyCastle: SRP6Util.calculateK(new SHA512Digest(), N, g).toString(16).toUpperCase()
        let expectedString_k512 = "5DF1C7A41B6EEB64E6EB12CC8BCC682BE86F5B33BE6A80B607421B436A613ADEDD13F8C58F216E78AE53B378E9BBCE1FCB48EF8D1870C11394DF228C7821D27F"
        
        let srp512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc)
        let k512 = srp512.calculate_k()
        let string_k_512 = String(k512, radix: 16, uppercase: true)
        XCTAssertEqual(string_k_512, expectedString_k512)
    }
    
    /// This test verifies calculation of the parameter x. Please note that we use the same formula for x as BouncyCastle does:
    /// x = H(s | H(I | ":" | p))  (| means concatenation and H is a hash function; SHA256 in this case)
    func test04Generate_x_SHA256()
    {
        let expected_x_256 = "65AC38DFF8BC34AE0F259E91FBD0F4CA2FA43081C9050CEC7CAC20D015F303"
        
        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc)
        
        let x_256 = srp256.bouncyCastle_x(s: s, I: I, p: p)
        
        let string_x_256 = String(x_256, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_x_256, expected_x_256)
    }

    /// This test verifies calculation of the parameter x. Please note that we use the same formula for x as BouncyCastle does:
    /// x = H(s | H(I | ":" | p))  (| means concatenation and H is a hash function; SHA512 in this case)
    func test04Generate_x_SHA512()
    {
        let expected_x_512 = "B149ECB0946B0B206D77E73D95DEB7C41BD12E86A5E2EEA3893D5416591A002FF94BFEA384DC0E1C550F7ED4D5A9D2AD1F1526F01C56B5C10577730CC4A4D709"
        
        let srp512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc)
        
        let x_512 = srp512.bouncyCastle_x(s: s, I: I, p: p)
        
        let string_x_512 = String(x_512, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_x_512, expected_x_512)
    }
    
    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA256 as the hashing function.
    func test05GenerateClientCredentials_SHA256()
    {
        let expectedString_x_256 = "65AC38DFF8BC34AE0F259E91FBD0F4CA2FA43081C9050CEC7CAC20D015F303"
        
        // a is fixed in this test (not generated randomly)
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!
        
        let expectedString_A_256 = "67945EDA6F2843D4619740F35387015D86CA0893BB204952BEB65E90B90CA93BADED1F450CEDD699C2A3D58E2203D17BBEF02B68484E43C31BF5A62B616EA516C94366E2009F2C0202E52B26F01BBC16BCB912DEC4FE3E42DAD9A853616B9373125C2C7EC3BD5FED929FF3BAA84C8F4AB0F1B081B7FC799BCFE5F8BDB707EEEB"


        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc, a: { _ in return fixed_a_256 })

        let (x_256, a_256, A_256) = srp256.generateClientCredentials(s: s, I: I, p: p)
        
        let string_x_256 = String(x_256, radix: 16, uppercase: true)
        let string_A_256 = String(A_256, radix: 16, uppercase: true)
        let string_a_256 = String(a_256, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_x_256, expectedString_x_256)
        XCTAssertEqual(string_a_256, fixedString_a_256)
        XCTAssertEqual(string_A_256, expectedString_A_256)
    }

    /// This test verifies correct computation of the client credentials by SRP.
    /// In this test we use a fixed parameter a (instead of generating a random one).
    /// Expected values (for the given fixed salt) were generated by BouncyCastle.
    /// This test is for SRP using SHA512 as the hashing function.
    func test05GenerateClientCredentials_SHA512()
    {
        let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
        let I = "alice".data(using: .utf8)!
        let p = "password123".data(using: .utf8)!
        
        let expectedString_x_512 = "B149ECB0946B0B206D77E73D95DEB7C41BD12E86A5E2EEA3893D5416591A002FF94BFEA384DC0E1C550F7ED4D5A9D2AD1F1526F01C56B5C10577730CC4A4D709"
        
        let fixedString_a_512 = "AF418FB99C9FFBAD427DEAE500F65A213F4855FD879E6F948103976F273D16377303A1339EF66150D882B15656E4CE18D8E894D72D0D671A85F34895F35A715698EC3D51DFE8F9D21D061B2409F6756EADE4714530E617140EFA13577498F5C3A0B3667489A66A6654D08E162EAE563BCF1FC05183435D31F1D0CF7F9B2B98C8"
        
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!
        
        let expectedString_A_512 = "9EEA5E7ED47AAE68209D6A520E3FDF7AF2E51582D89E1A35C83500216A77C2B6C4AC9ECF343827A0C5C524F7E4BD74FC66FE370A60AF7CBDB7911BD2A06EA5E164D55E0D269BA5B27A8DE199F0712769FFC195B4ABCF5D9CB286208E44841455BC5336091BC972B7CBE4A8596E370AC41DB6015A7B71251E410C56C309B62040"
        
        let srp_512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc, a: { _ in return fixed_a_512 })
        
        let (x_512, a_512, A_512) = srp_512.generateClientCredentials(s: s, I: I, p: p)
        
        let string_x_512 = String(x_512, radix: 16, uppercase: true)
        let string_A_512 = String(A_512, radix: 16, uppercase: true)
        let string_a_512 = String(a_512, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_x_512, expectedString_x_512)
        XCTAssertEqual(string_a_512, fixedString_a_512)
        XCTAssertEqual(string_A_512, expectedString_A_512)
        
    }
    
    /// Test to verify that the SRP verifier is calculated correctly (this version is for SHA256 hash function).
    func test06Verifier_SHA256()
    {
        let expectedStringVerifier_256 = "27E2855AC715F625981DBA238667955DB341A3BDD919868943BC049736C7804CD8E0507DFEFBF5B8573F5AAE7BAC19B257034254119AB520E1F7CF3F45D01B159016847201D14C8DC95EC34E8B26EE255BC4CB28D4F97E0DB97B65BDD196C4D2951CD84F493AFD7B34B90984357988601A3643358B81689DFD0CB0D21E21CF6E"
        
        // a is fixed in this test (not generated randomly)
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!
        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc, a: { _ in return fixed_a_256 })
        
        let v_256 = srp256.verifier(s: s, I: I, p: p)

        let string_v_256 = String(v_256, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_v_256, expectedStringVerifier_256)
    }
    
    /// Test to verify that the SRP verifier is calculated correctly (this version is for SHA512 hash function).
    func test06Verifier_SHA512()
    {
        let expectedStringVerifier_512 = "E714706A2A6C6C0478444006A15EA8625943ABDFA2C0AC9085CB174623304B71A55FD9A4114E089A05CD0E898B48294B6C842B333CE8141AFCE3FA54DD8D0ED6A950642AB0066858456219F88038D68FC4AFFCAABFEC4044BA484719ADDF2FE31AB5F02BBCAAC55B5765FB1827D9E7DE8150C5BA6C891DA9CBBE1B31F3B70B3F"

        // a is fixed in this test (not generated randomly)
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!
        let srp512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc, a: { _ in return fixed_a_512 })
        
        let v_512 = srp512.verifier(s: s, I: I, p: p)
        
        let string_v_512 = String(v_512, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_v_512, expectedStringVerifier_512)
        
    }
    
    /// This test verifies that the client and server way of calculating the shared secret produce the same shared secret value.
    /// (This version is for SHA256 hash function)
    func test07Verification_SHA256()
    {
        let expectedString_B_256 = "7695C1E721DB7A7ADA8F2091BF68F113D32F6027E28F8652D552FC898A6184580E97B4C11D0F9ECF5F7ABE23EBB33C61514C1770ABF722AE757D3E9CD5E5FC0F1C479D7F6203399F7A58483DD8C94B5802ED59720C0CA626F476FBFAFC2EE153BC1E468D0B23937267C7468A94BBADA15606870C6B1F87931294708A384231A8"
        
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!
        let fixed_b_256 = BigUInt(fixedString_b_256, radix: 16)!
        
        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc, a: { _ in return fixed_a_256 }, b: { _ in return fixed_b_256 })
        
        let v_256 = srp256.verifier(s: s, I: I, p: p)

        let (b_256, B_256) = srp256.generateServerCredentials(v: v_256)
        
        let string_b_256 = String(b_256, radix: 16, uppercase: true)
        let string_B_256 = String(B_256, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_b_256, fixedString_b_256)
        XCTAssertEqual(string_B_256, expectedString_B_256)
        
        let (x_256, a_256, A_256) = srp256.generateClientCredentials(s: s, I: I, p: p)
        
        let client_s_256 = try! srp256.calculateClientSecret(a: a_256, A:A_256, x: x_256, serverB: B_256)
        let server_s_256 = try! srp256.calculateServerSecret(clientA: A_256, v: v_256, b: b_256, B: B_256)
        
        let stringClient_s_256 = String(client_s_256, radix: 16, uppercase: true)
        let stringServer_s_256 = String(server_s_256, radix: 16, uppercase: true)
        
        XCTAssertEqual(stringClient_s_256, stringServer_s_256)
        
        // Verify the client evidence message.
        let M_256 = try! srp256.clientEvidenceMessage(a: a_256, A: A_256, x: x_256, serverB: B_256)
        
        let expectedStringM_256 = "795532FF6473671A589F05180E26AC39FEC22C290ADD5C7BEBF6609442129FEA"
        
        let stringM_256 = String(M_256, radix: 16, uppercase: true)
        XCTAssertEqual(stringM_256, expectedStringM_256)
    }
    
    /// This test verifies that the client and server way of calculating the shared secret produce the same shared secret value.
    /// (This version is for SHA512 hash function)
    func test07Verification_SHA512()
    {
        let expectedString_B_512 = "5B9BCD0D994B0C3BB04EF255B9C9FC6AFB9DBA26467A6F48AB2C42D925F33EB35956EE8D508012D2CA3702657370337939D4D5836353039B253BB1ADB8FE2987149E89B7527FE8598EB1107195FBC29B67C5BD5FA7B8D2CD667A6326E7531C4B8D7E6434656C732593728DB814EBBF90BCE8A8EEA254AC79F663269BFB8CD573"
        
        let fixed_a_512 = BigUInt(fixedString_a_512, radix: 16)!
        let fixed_b_512 = BigUInt(fixedString_b_512, radix: 16)!
        
        let srp512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc, a: { _ in return fixed_a_512 }, b: { _ in return fixed_b_512 })
        
        let v_512 = srp512.verifier(s: s, I: I, p: p)
        
        let (b_512, B_512) = srp512.generateServerCredentials(v: v_512)
        
        let string_b_512 = String(b_512, radix: 16, uppercase: true)
        let string_B_512 = String(B_512, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_b_512, fixedString_b_512)
        XCTAssertEqual(string_B_512, expectedString_B_512)
        
        let (x_512, a_512, A_512) = srp512.generateClientCredentials(s: s, I: I, p: p)
        
        let client_s_512 = try! srp512.calculateClientSecret(a: a_512, A:A_512, x: x_512, serverB: B_512)
        let server_s_512 = try! srp512.calculateServerSecret(clientA: A_512, v: v_512, b: b_512, B: B_512)
        
        let stringClient_s_512 = String(client_s_512, radix: 16, uppercase: true)
        let stringServer_s_512 = String(server_s_512, radix: 16, uppercase: true)
        
        XCTAssertEqual(stringClient_s_512, stringServer_s_512)
        
        // Verify the client evidence message.
        let M_512 = try! srp512.clientEvidenceMessage(a: a_512, A: A_512, x: x_512, serverB: B_512)
        
        let expectedStringM_512 = "79C9D1689A5D9721CD8AF63BE1C01D3F728FED2AD1D0DCFD5051CF729720BE6CF5C4DA7F7C135EFEBF7B2B45F2ADE4AB56B527231A2EAD0C8F23639BA578B92B"
        
        let stringM_512 = String(M_512, radix: 16, uppercase: true)
        XCTAssertEqual(stringM_512, expectedStringM_512)

    }
    
    
    
    
}
