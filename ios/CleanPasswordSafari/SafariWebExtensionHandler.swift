import SafariServices

/// The Safari extension: CleanPassword's browser extension (built from
/// extension/, as for Chrome) running in Safari on the iPhone, for what
/// AutoFill can't do there: offering to save a login after signing up or
/// in, and filling cards and identities. It keeps its own copy of the vault
/// (unlocked with the master password, synced with S3 like any device).
///
/// Messages from its pages (`browser.runtime.sendNativeMessage`) arrive
/// here; none are needed yet, so they're answered with an empty reply.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let reply = NSExtensionItem()
        reply.userInfo = [SFExtensionMessageKey: [String: String]()]
        context.completeRequest(returningItems: [reply], completionHandler: nil)
    }
}
