import XCTest
@testable import CleanPassword

/// The Rust core through its Swift bindings, as the app and the AutoFill
/// extension use it (syncing is covered by the core's own tests).
final class CoreTests: XCTestCase {
    let settings = S3Settings(bucket: "bucket", region: "us-east-1", prefix: "Vault", endpoint: nil)
    let keys = AwsKeys(accessKeyId: "AKIA", secretAccessKey: "secret", sessionToken: nil)
    let password = "a long master password"

    func login(_ name: String, _ url: String, user: String = "me", pw: String = "pw-1234") -> ItemFields {
        ItemFields(kind: .login, name: name, username: user, password: pw, websites: [Website(uri: url, matching: .default)], totp: "", notes: "", folder: "", favorite: false, fields: [])
    }

    func testCreateAddMatchAndUnlock() throws {
        let s = try VaultSession.create(settings: settings, keys: keys, password: password)
        let id = try s.add(fields: login("Example", "https://example.com"))
        _ = try s.add(fields: login("Other", "https://other.com"))
        XCTAssertEqual(s.items().count, 2)

        // AutoFill gives domains or URLs.
        XCTAssertEqual(s.matches(url: "example.com").map(\.id), [id])
        XCTAssertEqual(s.matches(url: "https://accounts.example.com/login").first?.exact, false)
        XCTAssertTrue(s.matches(url: "http://example.com").isEmpty, "never on plain http")

        let saved = s.save()
        XCTAssertFalse(saved.contains("pw-1234"))
        XCTAssertThrowsError(try VaultSession.unlock(saved: saved, password: "wrong password!")) { e in
            XCTAssertEqual(e as? CoreError, .WrongPassword)
        }
        let again = try VaultSession.unlockWithKey(saved: saved, key: s.key())
        XCTAssertEqual(again.get(id: id)?.fields.password, "pw-1234")
        XCTAssertEqual(lockedVault(saved: saved)?.settings, settings)
    }

    /// The app and its AutoFill extension each take in what the other
    /// saved, so neither's change is lost.
    func testAbsorbKeepsBothSidesChanges() throws {
        let app = try VaultSession.create(settings: settings, keys: keys, password: password)
        let shared = try app.add(fields: login("Shared", "https://shared.com"))
        let ext = try VaultSession.unlockWithKey(saved: app.save(), key: app.key())
        let fromExt = try ext.add(fields: login("Ext", "https://ext.com"))
        var f = try XCTUnwrap(app.get(id: shared)).fields
        f.notes = "edited in the app"
        XCTAssertTrue(try app.update(id: shared, fields: f))

        XCTAssertGreaterThanOrEqual(try app.absorb(saved: ext.save()), 1)
        XCTAssertNotNil(app.get(id: fromExt))
        XCTAssertEqual(app.get(id: shared)?.fields.notes, "edited in the app")
        XCTAssertEqual(try app.absorb(saved: app.save()), 0)

        let other = try VaultSession.create(settings: settings, keys: keys, password: password)
        XCTAssertThrowsError(try app.absorb(saved: other.save()))
    }

    func testPasswordHistoryAndTrash() throws {
        let s = try VaultSession.create(settings: settings, keys: keys, password: password)
        let id = try s.add(fields: login("Example", "https://example.com", pw: "old"))
        XCTAssertTrue(try s.update(id: id, fields: login("Example", "https://example.com", pw: "new")))
        XCTAssertEqual(s.get(id: id)?.history.map(\.password), ["old"])
        try s.delete(id: id)
        XCTAssertTrue(s.items().isEmpty)
        XCTAssertEqual(s.trash().count, 1)
        try s.restore(id: id)
        XCTAssertEqual(s.items().count, 1)
    }

    func testGeneratorAndCodes() throws {
        let pw = try generatePassword(recipe: .apple)
        XCTAssertEqual(pw.count, 20)
        XCTAssertEqual(pw.split(separator: "-").count, 3)
        XCTAssertGreaterThanOrEqual(passwordStrength(password: pw).score, 3)
        XCTAssertEqual(try oneTimeCode(secret: "JBSWY3DPEHPK3PXP").code.count, 6)
        XCTAssertFalse(isValidTotp(secret: "not a secret!"))
    }

    /// What the AutoFill extension does for a site: save a passkey, then
    /// sign in with it.
    func testPasskeys() throws {
        let s = try VaultSession.create(settings: settings, keys: keys, password: password)
        let reg = try s.createPasskey(rpId: "example.com", rpName: "Example", userHandle: Data("user-1".utf8), userName: "me@example.com", userDisplayName: "Me", itemId: nil)
        XCTAssertEqual(reg.credentialId.count, 16)
        XCTAssertEqual(reg.attestationObject.prefix(1), Data([0xa3]))
        let item = try XCTUnwrap(s.get(id: reg.itemId))
        XCTAssertEqual(item.passkeys.first?.rpId, "example.com")
        XCTAssertEqual(item.passkeys.first?.userHandle, Data("user-1".utf8))

        let options = s.passkeysFor(rpId: "example.com", allowed: [])
        XCTAssertEqual(options.map(\.credentialId), [reg.credentialId])
        XCTAssertTrue(s.passkeysFor(rpId: "other.com", allowed: []).isEmpty)
        let sig = try s.assertPasskey(itemId: reg.itemId, credentialId: reg.credentialId, rpId: "example.com", clientDataHash: Data(repeating: 7, count: 32))
        XCTAssertEqual(sig.userHandle, Data("user-1".utf8))
        XCTAssertEqual(sig.authenticatorData.count, 37)
        XCTAssertThrowsError(try s.assertPasskey(itemId: reg.itemId, credentialId: reg.credentialId, rpId: "evil.com", clientDataHash: Data(repeating: 7, count: 32)))

        try s.deletePasskey(itemId: reg.itemId, id: item.passkeys[0].id)
        XCTAssertTrue(s.passkeysFor(rpId: "example.com", allowed: []).isEmpty)
    }

    func testImportBitwardenJson() throws {
        let s = try VaultSession.create(settings: settings, keys: keys, password: password)
        let json = #"{"encrypted":false,"folders":[],"items":[{"type":1,"name":"GitHub","login":{"username":"octo","password":"x","uris":[{"uri":"https://github.com"}]}}]}"#
        let r = try s.importFile(text: json, password: nil)
        XCTAssertEqual(r.added, 1)
        XCTAssertEqual(s.matches(url: "github.com").first?.username, "octo")
    }

    /// A scanned setup QR code names the site and account for a new login.
    func testOtpauthLabel() {
        let a = CodeScannerView.label(of: "otpauth://totp/GitHub:octo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
        XCTAssertEqual(a.issuer, "GitHub")
        XCTAssertEqual(a.account, "octo@example.com")
        let b = CodeScannerView.label(of: "otpauth://totp/Example%20Co:me?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(b.issuer, "Example Co")
        XCTAssertEqual(b.account, "me")
        let c = CodeScannerView.label(of: "otpauth://totp/me?secret=JBSWY3DPEHPK3PXP")
        XCTAssertNil(c.issuer)
        XCTAssertEqual(c.account, "me")
        XCTAssertNil(CodeScannerView.label(of: "JBSWY3DPEHPK3PXP").account)
        XCTAssertTrue(isValidTotp(secret: "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"))
    }
}
