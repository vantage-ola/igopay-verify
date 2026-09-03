// A Secure Enclave signer for `igopay-publish`.
//
// The issuer's publication key lives in the Secure Enclave: generated there, never exportable,
// and used only through this helper. `igopay-publish` shells out to `sign`, hands it a 32-byte
// digest on stdin, and gets a signature back — it never sees, and cannot see, the key.
//
// Usage, matching what `igopay-publish --signer` expects:
//
//   igopay-publish-se create <keyfile> [--no-presence]   generate a key, print its public half
//   igopay-publish-se pubkey <keyfile>                   print the public half again
//   igopay-publish-se sign   <keyfile>                   digest hex on stdin, signature hex out
//
// ## What <keyfile> is, and is not
//
// It is the Enclave's own encrypted representation of the key — **not** the key. It is useless
// on any other machine, so it can be backed up freely, and backing it up is not optional: the
// Enclave will not hand out another copy. Lose the file and the key is gone even though the
// hardware still has it.
//
// Whether the file survives a macOS reinstall on the same hardware is NOT something this has
// been tested against, and it should not be assumed. Erasing the machine certainly destroys it.
// Treat the re-key procedure as the real backup plan, and rehearse it before publishing.
//
// ## Why user presence is the default
//
// This key signs every block list and every checkpoint for the whole system. Requiring Touch ID
// or the password per signature means a compromised process cannot publish on its own — it has
// to wait for a human, and a human who is not expecting a prompt is a human who now knows.
// A publication asks twice, because it signs two artefacts: the list, then the checkpoint.
//
// `--no-presence` exists for unattended publication. It is a real weakening and the tool says so.

import CryptoKit
import Foundation
import LocalAuthentication

// ---------------------------------------------------------------------------

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}

func note(_ message: String) {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ s: String) -> Data? {
    let chars = Array(s.trimmingCharacters(in: .whitespacesAndNewlines))
    guard chars.count % 2 == 0, !chars.isEmpty else { return nil }
    var out = Data(capacity: chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let b = UInt8(String(chars[i ... i + 1]), radix: 16) else { return nil }
        out.append(b)
        i += 2
    }
    return out
}

/// A 32-byte prehash presented as a `Digest`, so the Enclave can sign it directly.
///
/// CryptoKit will not let you pass raw bytes where a digest is expected, and it is right not to.
/// This protocol is the intended way through, and it is what a `SecureEnclave` key requires:
/// `signature(for:)` takes a `Digest`, and the core hands out a SHA-256 body digest.
struct PrehashDigest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]

    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    var description: String { "PrehashDigest(32 bytes)" }
}

func loadKey(_ path: String) -> SecureEnclave.P256.Signing.PrivateKey {
    guard let blob = FileManager.default.contents(atPath: path) else {
        die("cannot read \(path). Run `create` first, or restore your backup of it.")
    }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    } catch {
        die("""
        \(path) is not usable by this machine's Secure Enclave: \(error)

        The blob is bound to one Enclave. If this is a different Mac, or the machine has been
        erased, the key is gone and you need your re-key procedure — not this tool.
        """)
    }
}

// ---------------------------------------------------------------------------

let args = CommandLine.arguments
guard args.count >= 3 else {
    note("""
    igopay-publish-se — hold the issuer's publication key in the Secure Enclave

    USAGE
      igopay-publish-se create <keyfile> [--no-presence]
      igopay-publish-se pubkey <keyfile>
      igopay-publish-se sign   <keyfile>      # digest hex on stdin, signature hex on stdout

    Wire it into the publisher with:
      igopay-publish init <dir> --issuer <pubkey-hex> \\
        --signer 'igopay-publish-se sign <keyfile>'
    """)
    exit(2)
}

let command = args[1]
let keyfile = args[2]

guard SecureEnclave.isAvailable else {
    die("""
    this machine has no Secure Enclave.

    Every Apple-silicon Mac and every Mac with a T2 has one. On anything else, choose a different
    custody option — a PKCS#11 token or a cloud KMS both work through the same `--signer` seam.
    """)
}

switch command {
case "create":
    if FileManager.default.fileExists(atPath: keyfile) {
        die("""
        \(keyfile) already exists.

        Refusing to overwrite it. If a key here has ever signed a publication, replacing it
        silently would leave a log whose later entries verify under a key nobody was told about —
        every device would reject them, and the log would look rewritten.
        """)
    }

    let wantsPresence = !args.contains("--no-presence")
    var key: SecureEnclave.P256.Signing.PrivateKey
    if wantsPresence {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        ) else {
            die("could not build the access control policy: \(error!.takeRetainedValue())")
        }
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            die("could not create the key: \(error)")
        }
    } else {
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey()
        } catch {
            die("could not create the key: \(error)")
        }
    }

    do {
        try key.dataRepresentation.write(to: URL(fileURLWithPath: keyfile), options: [.withoutOverwriting])
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: keyfile)
    } catch {
        die("could not write \(keyfile): \(error)")
    }

    let pub = hex(key.publicKey.compressedRepresentation)
    note("Created a Secure Enclave P-256 key.")
    note("  blob            \(keyfile) (\(key.dataRepresentation.count) bytes, mode 600)")
    note("  user presence   \(wantsPresence ? "required per signature" : "NOT required — weaker, and deliberate")")
    note("")
    note("Public key — this is what the issuer publishes and every device verifies against:")
    print(pub)
    note("""

    Next:
      igopay-publish init <dir> --issuer \(pub) \\
        --signer '\(CommandLine.arguments[0]) sign \(keyfile)'

    Then back up \(keyfile). It is not the key and is worthless on another machine, but the
    Enclave will not give you a second copy, so losing the file loses the key.
    """)

case "pubkey":
    print(hex(loadKey(keyfile).publicKey.compressedRepresentation))

case "sign":
    guard let line = readLine(strippingNewline: true), let digest = unhex(line) else {
        die("expected a hex digest on stdin")
    }
    guard digest.count == 32 else {
        die("expected a 32-byte digest, got \(digest.count) bytes")
    }
    let key = loadKey(keyfile)
    do {
        let sig = try key.signature(for: PrehashDigest(bytes: [UInt8](digest)))
        // Raw r‖s, which is the wire format. Not normalised to low-S here on purpose:
        // `igopay-publish` normalises whatever it is given and then verifies the result, so that
        // rule lives in exactly one place rather than in every signer somebody writes.
        print(hex(sig.rawRepresentation))
    } catch {
        die("the Enclave refused to sign: \(error)")
    }

default:
    die("unknown command `\(command)`")
}
