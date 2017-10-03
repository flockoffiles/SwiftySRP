//
//  FFDataWrapperTests.swift
//  FFDataWrapperTests
//
//  Created by Sergey Novitsky on 21/09/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import XCTest
@testable import FFDataWrapper

extension Data
{
    /// Convert data to a hex string
    ///
    /// - Returns: hex string representation of the data.
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

func address(o: UnsafeRawPointer) -> UnsafeRawPointer
{
    return o
}


class FFDataWrapperTests: XCTestCase
{
    class DeinitLogger
    {
        let name: String
        init(name: String)
        {
            self.name = name
        }
        
        deinit {
            print("---- deinit for: \(name)")
        }
    }
    
    struct DummyStruct
    {
        let dummy: Int = 123456
    }
    
    struct TestStruct
    {
        var dummy = DummyStruct()
//        var classField1 = DeinitLogger(name: "classField1")
//        var structField1: [DeinitLogger] = [DeinitLogger(name: "structField1")]
//        var classField2 = DeinitLogger(name: "classField2")
//        var data: Data
        
        
        init(string: String)
        {
//            let length = string.lengthOfBytes(using: .utf8)
//            print("length = \(length)")
//            let cString = string.utf8CString
//            data = Data(count: length)
//            data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> Void in
//                for i in 0 ..< length
//                {
//                    bytes[i] = UInt8(cString[i])
//                }
//            }
//            print("data = \(data.hexString())")
            let dummyAddrString = String(format:"0x%x", Int(bitPattern:address(o: &dummy)))
            print("address of dummy = \(dummyAddrString)")
        }
    }
    

    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    let testString = "ABCD"

    func testAddresses()
    {
        var testStruct = TestStruct(string: testString)
        let testStructAddress = address(o: &testStruct)
        print(String(format:"0x%x", Int(bitPattern: testStructAddress)))
        print(String(format:"0x%x", Int(bitPattern: address(o: &testStruct.dummy))))
        let dummy = testStructAddress.assumingMemoryBound(to: TestStruct.self).pointee.dummy.dummy
        print("dummy = \(dummy)")
    }
    
    func testWrapStringWithXOR()
    {
        
        let wrapper1 = FFDataWrapper(testString)
        
        var recoveredString = ""
        wrapper1.withDecodedData {
            recoveredString = String(data: $0, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }
        
        print(wrapper1.dataRef.dataBuffer)
        let testData = testString.data(using: .utf8)!
        let underlyingData = Data(bytes: wrapper1.dataRef.dataBuffer, count: wrapper1.dataRef.length)
        XCTAssertNotEqual(underlyingData, testData)

        
        let wrapper2 = wrapper1
        wrapper2.withDecodedData { data in
            recoveredString = String(data: data, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }
        
    }
    
    func testWraperStringWithCopy()
    {
        let wrapper1 = FFDataWrapper(testString, FFDataWrapperEncoders.identity.coders)
        
        var recoveredString = ""
        wrapper1.withDecodedData {
            recoveredString = String(data: $0, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }
        
        let testData = testString.data(using: .utf8)!
        let underlyingData = Data(bytes: wrapper1.dataRef.dataBuffer, count: wrapper1.dataRef.length)
        XCTAssertEqual(underlyingData, testData)
        
        let wrapper2 = wrapper1
        wrapper2.withDecodedData {
            recoveredString = String(data: $0, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }
    }
    
    func testWraperDataWithXOR()
    {
        let testData = testString.data(using: .utf8)!
        
        let wrapper1 = FFDataWrapper(testData)
        
        var recoveredString = ""
        wrapper1.withDecodedData {
            recoveredString = String(data: $0, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }

        let underlyingData = Data(bytes: wrapper1.dataRef.dataBuffer, count: wrapper1.dataRef.length)
        XCTAssertNotEqual(underlyingData, testData)

        let wrapper2 = wrapper1
        wrapper2.withDecodedData {
            recoveredString = String(data: $0, encoding: .utf8)!
            XCTAssertEqual(recoveredString, testString)
        }
    }
    
    
}
