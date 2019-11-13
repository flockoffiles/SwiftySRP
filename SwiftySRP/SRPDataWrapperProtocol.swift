//
//  SRPDataWrapperProtocol.swift
//  SwiftySRP
//
//  Created by Sergey Novitsky on 06/11/2019.
//  Copyright © 2019 Flock of Files. All rights reserved.
//

import Foundation

public protocol SRPDataWrapperProtocol: Codable {
    /// Default initializer
    init()
    init(data: inout Data)
    init(dataFunc: () throws -> Data) rethrows
    
    func map<ResultType>(_ block: (inout Data) throws -> ResultType) rethrows -> ResultType
    var isEmpty: Bool { get }
    
    static func wipe(_ data: inout Data)
}
