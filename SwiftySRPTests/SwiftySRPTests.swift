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
    
    func test01StringConversion()
    {
        XCTAssertEqual(N_asString, String(N, radix: 16, uppercase: true))
        XCTAssertEqual(g_asString, String(g, radix: 16, uppercase: true))
    }
    
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
    
    /// This test verifies calculation of the parameter k = H(N, g) for H = SHA256 and H = SHA512
    func test03Generate_k()
    {
        // Generated with BouncyCastle: SRP6Util.calculateK(new SHA256Digest(), N, g).toString(16).toUpperCase()
        let expectedString_k256 = "1A1A4C140CDE70AE360C1EC33A33155B1022DF951732A476A862EB3AB8206A5C"
        
        // Generated with BouncyCastle: SRP6Util.calculateK(new SHA512Digest(), N, g).toString(16).toUpperCase()
        let expectedString_k512 = "5DF1C7A41B6EEB64E6EB12CC8BCC682BE86F5B33BE6A80B607421B436A613ADEDD13F8C58F216E78AE53B378E9BBCE1FCB48EF8D1870C11394DF228C7821D27F"

        let srp256 = SRP(N: N, g:g, digest: SRP.sha256DigestFunc)
        let srp512 = SRP(N: N, g:g, digest: SRP.sha512DigestFunc)
        
        let k256 = srp256.calculate_k()
        let k512 = srp512.calculate_k()
        
        let string_k_256 = String(k256, radix: 16, uppercase: true)
        let string_k_512 = String(k512, radix: 16, uppercase: true)
        
        XCTAssertEqual(string_k_256, expectedString_k256)
        XCTAssertEqual(string_k_512, expectedString_k512)
    }
    
    func test04Generate_x()
    {
        let expected_x_256 = "65AC38DFF8BC34AE0F259E91FBD0F4CA2FA43081C9050CEC7CAC20D015F303"
        let expected_x_512 = "B149ECB0946B0B206D77E73D95DEB7C41BD12E86A5E2EEA3893D5416591A002FF94BFEA384DC0E1C550F7ED4D5A9D2AD1F1526F01C56B5C10577730CC4A4D709"
        
        
        
    }

    
    
}
