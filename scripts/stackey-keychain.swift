import Foundation
import LocalAuthentication
import Security

let service = "app.stackey.vault"

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}

guard CommandLine.arguments.count == 3 else { fail("usage: stackey-keychain store|load|delete <vault-id>") }
let op = CommandLine.arguments[1]
let account = CommandLine.arguments[2]
guard account.range(of: "^[0-9a-f-]{36}$", options: .regularExpression) != nil else { fail("invalid account") }

let query: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrService as String: service,
  kSecAttrAccount as String: account,
]

switch op {
case "store":
  let secret = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? ""
  guard !secret.isEmpty, secret.count <= 512 else { fail("invalid secret") }
  SecItemDelete(query as CFDictionary)
  var error: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.userPresence],
    &error
  ) else { fail("access control") }
  var add = query
  add[kSecValueData as String] = Data(secret.utf8)
  add[kSecAttrAccessControl as String] = access
  add[kSecUseAuthenticationContext as String] = LAContext()
  let status = SecItemAdd(add as CFDictionary, nil)
  guard status == errSecSuccess else { fail("store \(status)") }
case "load":
  var result: AnyObject?
  var load = query
  load[kSecReturnData as String] = true
  load[kSecMatchLimit as String] = kSecMatchLimitOne
  load[kSecUseOperationPrompt as String] = "Unlock Stackey vault"
  let status = SecItemCopyMatching(load as CFDictionary, &result)
  guard status == errSecSuccess, let data = result as? Data, let secret = String(data: data, encoding: .utf8) else {
    fail(status == errSecUserCanceled || status == errSecAuthFailed ? "denied" : "missing")
  }
  FileHandle.standardOutput.write(Data(secret.utf8))
case "delete":
  SecItemDelete(query as CFDictionary)
default:
  fail("usage")
}
