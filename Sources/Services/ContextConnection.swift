/*-
 * ---license-start
 * eu-digital-green-certificates / dgca-app-core-ios
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */
//
//  ContextConnection.swift
//
//
//  Created by Yannick Spreen on 5/12/21.
//

import Foundation
import SwiftyJSON
import Alamofire

public protocol ContextConnection {
  static var config: JSON { get }
}

var alamofireSessions = [String: SessionManager]()

public extension ContextConnection {
  static func request(
    _ path: [String],
    externalLink: String? = nil,
    method: HTTPMethod = .get,
    parameters: Parameters? = nil,
    encoding: ParameterEncoding = URLEncoding.default,
    headers: HTTPHeaders? = nil,
    adapter: RequestAdapter? = nil,
    retrier: RequestRetrier? = nil
//    requestModifier: SessionManager.RequestModifier? = nil
  ) -> DataRequest {
    var json = config
    for key in path {
      json = json[key]
    }
    let url = (json["url"].string ?? "") + (externalLink ?? "")
    if alamofireSessions[url] == nil {
        var keys = ["*"]
        if json["pubKeys"].exists() {
            keys = json["pubKeys"].array?.compactMap { $0.string } ?? []
        }
        let host = URL(string: url)?.host ?? ""
        var evaluators: [String: ServerTrustPolicy] = [:]
        evaluators["\(host)-revoke"] = ServerTrustPolicy.performRevokedEvaluation(validateHost: true, revocationFlags: kSecRevocationCRLMethod)
        evaluators["\(host)-custom"] = ServerTrustPolicy.customEvaluation { (trust: SecTrust, host:String) in
            var hashes: [String] = []
            if let key = SecTrustCopyPublicKey(trust), let der = SecKeyCopyExternalRepresentation(key, nil) {
                hashes.append(SHA256.digest(input: der as NSData).base64EncodedString())
            }
//            let hashes: [String] =
//                trust.af.publicKeys.compactMap { key in
//              guard
//                let der = SecKeyCopyExternalRepresentation(key, nil)
//              else {
//                return nil
//              }
//              return SHA256.digest(input: der as NSData).base64EncodedString()
//            }
            for hash in (hashes + ["*"]) {
              if keys.contains(hash) {
                #if DEBUG && targetEnvironment(simulator)
                print("SSL Pubkey matches. ✅")
                #endif
                return true
              }
            }
            #if !DEBUG || !targetEnvironment(simulator)
            let failure = true
            #else
            let failure = false
            #endif
            if failure && 0 < 1 { // silence unreachable warning
              print("oops")
            }
            print("\nFATAL: None of the hashes matched our public keys! These keys were loaded:")
            print(keys.joined(separator: "\n"))
            print("\nThe server returned this chain:")
            print(hashes.joined(separator: "\n"))
            return false
        }
        let trust = ServerTrustPolicyManager(policies: evaluators)
        alamofireSessions[url] = SessionManager(configuration: .default, serverTrustPolicyManager: trust)
        alamofireSessions[url]?.retrier = retrier
        alamofireSessions[url]?.adapter = adapter
    }
    let session = alamofireSessions[url]!// ?? AF
    return session.request(
      url,
      method: method,
      parameters: parameters,
      encoding: encoding,
      headers: headers
//      interceptor: interceptor,
//      requestModifier: requestModifier
    )
  }
}
