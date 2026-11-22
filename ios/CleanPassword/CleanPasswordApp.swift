import SwiftUI

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
        .alert("CleanPassword", isPresented: Binding(get: { store.notice != nil }, set: { if !$0 { store.notice = nil } })) {
            Button("OK") { store.notice = nil }
        } message: {
            Text(store.notice ?? "")
        }
    }
}
