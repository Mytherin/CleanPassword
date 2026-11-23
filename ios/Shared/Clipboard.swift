import UIKit
import UniformTypeIdentifiers

/// The clipboard settings, shared by the app and its AutoFill extension.
enum Clipboard {
    static let clearKey = "clipboardSeconds"
    static let copyCodeKey = "copyCodeAfterFill"
    static var defaults: UserDefaults { UserDefaults(suiteName: AppGroup.id) ?? .standard }

    /// Seconds before something copied is cleared (0: never).
    static var clearAfter: Int { defaults.object(forKey: clearKey) as? Int ?? 90 }

    /// Whether filling a login that has a verification code also copies
    /// its current code, for the site's next step (as Bitwarden does).
    static var copyCodeAfterFill: Bool { defaults.object(forKey: copyCodeKey) as? Bool ?? true }
}

/// Copies to the clipboard on this device only (not to other devices
/// through Universal Clipboard), cleared after the time set in Settings.
func copySecret(_ text: String) {
    var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
    if Clipboard.clearAfter > 0 { options[.expirationDate] = Date().addingTimeInterval(TimeInterval(Clipboard.clearAfter)) }
    UIPasteboard.general.setItems([[UTType.plainText.identifier: text]], options: options)
}
