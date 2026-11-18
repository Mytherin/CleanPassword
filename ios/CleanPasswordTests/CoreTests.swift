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

    func testImportBitwardenJson() throws {
        let s = try VaultSession.create(settings: settings, keys: keys, password: password)
        let json = #"{"encrypted":false,"folders":[],"items":[{"type":1,"name":"GitHub","login":{"username":"octo","password":"x","uris":[{"uri":"https://github.com"}]}}]}"#
        let r = try s.importFile(text: json, password: nil)
        XCTAssertEqual(r.added, 1)
        XCTAssertEqual(s.matches(url: "github.com").first?.username, "octo")
    }
}
