import SwiftUI
import UIKit

@main
struct CleanPasswordApp: App {
    @StateObject private var store = VaultStore()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                // otpauth:// links: verification codes to set up.
                .onOpenURL { store.open(url: $0) }
        }
        .onChange(of: phase) { _, phase in
            switch phase {
            case .background: store.enteredBackground()
            case .active: store.enteredForeground()
            default: break
            }
        }
    }
}

/// Setting up, unlocking, or the navigation stack from the Passwords
/// screen; the vault is hidden behind a lock in the app switcher.
struct RootView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.scenePhase) private var phase
    @State private var path: [Route] = []

    var body: some View {
        ZStack {
            switch store.phase {
            case .setup: SetupView()
            case .locked(let info): UnlockView(info: info)
            case .unlocked:
                NavigationStack(path: $path) {
                    PasswordsView(path: $path)
                        .navigationDestination(for: Route.self) { route in
                            switch route {
                            case .list(let c): ItemListView(category: c)
                            case .item(let id): ItemDetailView(id: id)
                            }
                        }
                }
            }
            if phase != .active && store.phase == .unlocked {
                Color(.systemBackground).ignoresSafeArea()
                Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
            }
        }
        .onChange(of: store.phase) { _, p in
            if p != .unlocked { path = [] }
        }
        .onChange(of: phase) { _, p in
            if p != .active && store.phase == .unlocked { PrivacyCover.show() } else if p == .active { PrivacyCover.hide() }
        }
        .alert("CleanPassword", isPresented: Binding(get: { store.notice != nil }, set: { if !$0 { store.notice = nil } })) {
            Button("OK") { store.notice = nil }
        } message: {
            Text(store.notice ?? "")
        }
    }
}

/// A cover over everything the app shows, sheets and alerts included (they
/// sit above the root view, so a cover inside it ends up under them): what
/// the app switcher's snapshot shows while the vault is unlocked.
@MainActor
enum PrivacyCover {
    private static var window: UIWindow?

    static func show() {
        guard window == nil,
              let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first
        else { return }
        let w = UIWindow(windowScene: scene)
        w.rootViewController = UIHostingController(rootView: CoverView())
        w.windowLevel = .alert + 1
        w.isHidden = false
        window = w
    }

    static func hide() {
        window?.isHidden = true
        window = nil
    }
}

private struct CoverView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
        }
    }
}
