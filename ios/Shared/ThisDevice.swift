import UIKit

/// What to call this device in the app's text: the vault is kept, and the
/// PIN works, on this one only.
enum ThisDevice {
    @MainActor static let name: String = {
        #if targetEnvironment(macCatalyst)
        return "Mac"
        #else
        return UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
        #endif
    }()
}
