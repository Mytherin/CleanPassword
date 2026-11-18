import SwiftUI

@main
struct CleanPasswordApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: model.enteredBackground()
            case .active: model.enteredForeground()
            default: break
            }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            switch model.phase {
            case .setup: SetupView()
            case .locked(let info): UnlockView(info: info)
            case .unlocked: VaultListView()
            }
            // Hide the vault in the app switcher's snapshot.
            if scenePhase != .active && model.phase == .unlocked {
                Color(.systemBackground).ignoresSafeArea()
                Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
            }
        }
        .alert("CleanPassword", isPresented: Binding(get: { model.notice != nil }, set: { if !$0 { model.notice = nil } })) {
            Button("OK") { model.notice = nil }
        } message: {
            Text(model.notice ?? "")
        }
    }
}
