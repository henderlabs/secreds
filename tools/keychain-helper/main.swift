// seCreds Keychain helper. Signed with a stable identity so Keychain grants belong to seCreds, not to Python.
// It never prints a secret except `get`, which writes the value to stdout for the calling seCreds process.
// It makes no policy decisions: seCreds (Python) still checks agents, allowlists, windows and revocation first.
import Foundation
import Security
import LocalAuthentication

let service = ProcessInfo.processInfo.environment["SECREDS_SERVICE"] ?? "secreds"
func fail(_ msg: String, _ code: Int32) -> Never { FileHandle.standardError.write(Data((msg + "\n").utf8)); exit(code) }
func q(_ name: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name]
}
// Exit codes: 0 ok, 44 not found, 45 user cancelled/denied, 46 other OSStatus (number on stderr)
func code(_ st: OSStatus) -> Int32 {
    switch st {
    case errSecSuccess: return 0
    case errSecItemNotFound: return 44
    case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed: return 45
    default: return 46
    }
}
func die(_ what: String, _ st: OSStatus) -> Never { fail("\(what) (OSStatus \(st))", code(st)) }

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: seCreds-kc get|set|has|delete|touchid|trust|ident NAME", 2) }
let cmd = args[1], name = args.count > 2 ? args[2] : ""

switch cmd {
case "ident":   // which signing identity this binary runs as (no secrets)
    var me: SecCode?; SecCodeCopySelf([], &me)
    var st: SecStaticCode?; if let me { SecCodeCopyStaticCode(me, [], &st) }
    var info: CFDictionary?
    if let st { SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation), &info) }
    let d = info as? [String: Any] ?? [:]
    print("identifier=\(d[kSecCodeInfoIdentifier as String] ?? "?") team=\(d[kSecCodeInfoTeamIdentifier as String] ?? "none")")
case "has":
    exit(code(SecItemCopyMatching(q(name) as CFDictionary, nil)))
case "get":
    var out: AnyObject?
    var d = q(name); d[kSecReturnData as String] = true
    let st = SecItemCopyMatching(d as CFDictionary, &out)
    guard st == errSecSuccess, let data = out as? Data else { die("Keychain read failed", st) }
    FileHandle.standardOutput.write(data)
case "set":
    let data = FileHandle.standardInput.readDataToEndOfFile()
    var st = SecItemUpdate(q(name) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if st == errSecItemNotFound {
        var d = q(name); d[kSecValueData as String] = data
        st = SecItemAdd(d as CFDictionary, nil)
    }
    if st != errSecSuccess { die("Keychain write failed", st) }
case "delete":
    let st = SecItemDelete(q(name) as CFDictionary)
    if st != errSecSuccess && st != errSecItemNotFound { die("Keychain delete failed", st) }
case "touchid":   // reason in argv[2]; exit 0 only if approved
    let ctx = LAContext(); var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { exit(1) }
    let sem = DispatchSemaphore(value: 0); var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: name.isEmpty ? "confirm this action" : name) { s, _ in ok = s; sem.signal() }
    _ = sem.wait(timeout: .now() + 120)
    exit(ok ? 0 : 1)
case "trust":   // add this helper to an item's access list. Does not read the secret. May ask for the login password.
    var d = q(name); d[kSecReturnRef as String] = true
    var ref: AnyObject?
    var st = SecItemCopyMatching(d as CFDictionary, &ref)
    guard st == errSecSuccess, let item = ref else { die("item lookup failed", st) }
    let it = item as! SecKeychainItem
    var access: SecAccess?
    st = SecKeychainItemCopyAccess(it, &access)
    guard st == errSecSuccess, let acc = access else { die("could not read access list", st) }
    var me: SecTrustedApplication?; SecTrustedApplicationCreateFromPath(nil, &me)
    var aclsRef: CFArray?
    SecAccessCopyACLList(acc, &aclsRef)
    var changed = 0
    for a in (aclsRef as? [SecACL]) ?? [] {
        var apps: CFArray?; var desc: CFString?; var sel = SecKeychainPromptSelector()
        guard SecACLCopyContents(a, &apps, &desc, &sel) == errSecSuccess else { continue }
        guard let apps0 = apps as? [SecTrustedApplication] else { continue }   // nil = "any app" or non-app entry: leave alone
        var list = apps0; if let me { list.append(me) }
        if SecACLSetContents(a, list as CFArray, desc ?? "" as CFString, sel) == errSecSuccess { changed += 1 }
    }
    st = SecKeychainItemSetAccess(it, acc)
    if st != errSecSuccess { die("could not save access list", st) }
    print("trusted (\(changed) entries)")
default:
    fail("unknown command", 2)
}
