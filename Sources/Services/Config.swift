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
//  Config.swift
//
//
//  Created by Yannick Spreen on 5/12/21.
//

import Foundation
import SwiftyJSON

public struct Config {
  public static func merge(_ old: JSON, with new: JSON) -> JSON {
    old.mergeAndOverride(other: new)
  }

  public static func load() -> JSON {
    guard
      let path = Bundle.main.resourcePath
    else {
      return .null
    }

    let context = "context.jsonc"
    let fileURL = URL(fileURLWithPath: path + "/\(context)")
    guard let fileContents = try? Data(contentsOf: fileURL) else {
      return .null
    }
    let string = String(data: fileContents, encoding: .utf8) ?? ""
    return JSON(parseJSONC: string)
  }
}
