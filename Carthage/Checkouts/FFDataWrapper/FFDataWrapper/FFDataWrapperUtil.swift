//
//  FFDataWrapperUtil.swift
//  FFDataWrapper
//
//  Created by Sergey Novitsky on 29/09/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

import Foundation

public extension FFDataWrapper
{
    /// Wipe the contents of data by zeroing out internal storage.
    ///
    /// - Parameter data: The data to wipe
    public static func wipe(_ data: inout Data)
    {
        data.resetBytes(in: 0 ..< data.count)
        data.removeAll()
    }

    /// Try to wipe to contents of the underlying storage by replacing the characters with '\0'
    /// (That's the best that we can hope for given current Swift's implementation. It works at least for ASCII and UTF8 strings)
    /// - Parameter string: The string to wipe.
    public static func wipe(_ string: inout String)
    {
        let empty = String(repeating: "\0", count: string.count)
        string.withMutableCharacters {
            $0.replaceSubrange($0.startIndex ..< $0.endIndex, with: empty)
        }
        string.removeAll()
    }

}


