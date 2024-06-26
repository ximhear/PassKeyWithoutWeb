//
//  Base64.swift
//  PassKey
//
//  Created by gzonelee on 6/25/24.
//

import Foundation

func base64UrlDecode(_ base64Url: String) -> Data? {
    var base64 = base64Url
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    
    let paddingLength = 4 - (base64.count % 4)
    if paddingLength < 4 {
        base64.append(String(repeating: "=", count: paddingLength))
    }
    
    return Data(base64Encoded: base64)
}
