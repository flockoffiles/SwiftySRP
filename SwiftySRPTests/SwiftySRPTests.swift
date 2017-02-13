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

/// Tests for SRP functions.
/// Based on similar tests in BouncyCastle, but uses different hash functions (SHA256 and SHA512).
/// Expected values for the tests were generated with BouncyCastle (which is assumed to be correct).
class SwiftySRPTests: XCTestCase
{
    let N_asString = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"
                    + "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"
                    + "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"
                    + "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"
                    + "FD5138FE8376435B9FC61D2FC0EB06E3"

    let g_asString = "2"
    
    var N: BigUInt = BigUInt()
    var g: BigUInt = BigUInt()

    override func setUp()
    {
        super.setUp()
        
        N = BigUInt(N_asString, radix: 16)!
        g = BigUInt(g_asString, radix: 16)!
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
        
        let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
        let I = "alice".data(using: .utf8)!
        let p = "password123".data(using: .utf8)!

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
        
        let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
        let I = "alice".data(using: .utf8)!
        let p = "password123".data(using: .utf8)!
        
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
        
        let fixedString_a_256 = "D2BC7017556329B81DCE85E939ED7AD070F65B4D10DDD765A50BB1D5B4C00DB75598CB787884E0987572D9FCA5B4537677DF459BA009D971F03E21E48A6EFB6B84CFD340E0419EF039778C2F6EC5057BF2F7D4F62E7758791ADB75AF48F70F8709A824E59BEEFAEC5743B06E1F5D59C36054AB0D69C8D0EC606FA8030F10C652"

        // a is fixed in this test (not generated randomly)
        let fixed_a_256 = BigUInt(fixedString_a_256, radix: 16)!
        
        let expectedString_A_256 = "67945EDA6F2843D4619740F35387015D86CA0893BB204952BEB65E90B90CA93BADED1F450CEDD699C2A3D58E2203D17BBEF02B68484E43C31BF5A62B616EA516C94366E2009F2C0202E52B26F01BBC16BCB912DEC4FE3E42DAD9A853616B9373125C2C7EC3BD5FED929FF3BAA84C8F4AB0F1B081B7FC799BCFE5F8BDB707EEEB"

        let s = BigUInt("BEB25379D1A8581EB5A727673A2441EE", radix: 16)!.serialize()
        let I = "alice".data(using: .utf8)!
        let p = "password123".data(using: .utf8)!

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
    
    
}
