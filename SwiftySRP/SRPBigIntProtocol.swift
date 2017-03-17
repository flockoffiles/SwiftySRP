//
//  SRPBigIntProtocol.swift
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 17/03/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

public protocol SRPBigIntProtocol: Comparable
{
    init()
    
    init(_ intValue: Int)
    
    init(_ data: Data)
    
    init(_ other: Self)
    
    func serialize() -> Data
    
    var width: Int { get }
    
    static func %(x: Self, y: Self) -> Self
    
    static func *(x: Self, y: Self) -> Self
    
    static func +(a: Self, b: Self) -> Self
    
    static func -(a: Self, b: Self) -> Self
    
    func power(_ exponent: Self, modulus: Self) -> Self
    
    static func randomIntegerLessThan(_ limit: Self) -> Self
}
