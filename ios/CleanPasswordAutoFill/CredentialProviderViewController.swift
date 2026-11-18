import AuthenticationServices
import SwiftUI

/// The AutoFill extension: what iOS opens from the keyboard's "Passwords"
/// button, the suggestions above it, and Safari's sign-in sheets. It unlocks
/// the vault this device keeps (Face ID, or the master password), offers the
/// logins for the site, and hands the chosen one to iOS. It only reads the
/// vault; the app syncs and edits it.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let model = ExtensionModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        model.complete = { [weak self] user, password in
            self?.extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password), completionHandler: nil)
        }
        model.cancel = { [weak self] in
            self?.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
        }
        let host = UIHostingController(rootView: ExtensionView().environmentObject(model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    /// The list of logins for the sites the app or page asks about.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.services = serviceIdentifiers.map(\.identifier)
        model.mode = .list
    }

    /// A suggestion above the keyboard was picked. The vault is locked
    /// whenever the extension starts, so this always needs the user (Face ID).
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    /// …so iOS shows the extension for it: unlock, then hand over that login.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        model.wanted = credentialRequest.credentialIdentity.recordIdentifier
        model.services = [credentialRequest.credentialIdentity.serviceIdentifier.identifier]
        model.mode = .list
    }

    /// Turned on in Settings: nothing to configure here.
    override func prepareInterfaceForExtensionConfiguration() {
        model.mode = .configured
    }
}

@MainActor
final class ExtensionModel: ObservableObject {
    enum Mode { case list, configured }

    @Published var mode: Mode = .list
    @Published var unlocked = false
    @Published var matches: [SuggestedLogin] = []
    @Published var all: [VaultItem] = []
    @Published var error: String?
    var services: [String] = []
    var wanted: String?
    var complete: (String, String) -> Void = { _, _ in }
    var cancel: () -> Void = {}
    private var session: VaultSession?

    var info: LockedVault? { SavedVault.load().flatMap { lockedVault(saved: $0) } }

    var site: String {
        guard let s = services.first else { return "" }
        return URL(string: s)?.host ?? s
    }

    func tryBiometrics() async {
        guard let saved = SavedVault.load(), let id = info?.vaultId, BiometricKey.exists(vaultId: id) else { return }
        let key = await Task.detached { BiometricKey.read(vaultId: id, reason: "Fill a password") }.value
        guard let key, let s = try? VaultSession.unlockWithKey(saved: saved, key: key) else { return }
        opened(s)
    }

    func unlock(password: String) async {
        guard let saved = SavedVault.load() else { return }
        do {
            let s = try await Task.detached { try VaultSession.unlock(saved: saved, password: password) }.value
            opened(s)
        } catch {
            self.error = describe(error)
        }
    }

    private func opened(_ s: VaultSession) {
        session = s
        unlocked = true
        if let id = wanted, let item = s.get(id: id) {
            return complete(item.fields.username, item.fields.password)
        }
        var seen = Set<String>()
        matches = services.flatMap { s.matches(url: $0) }.filter { seen.insert($0.id).inserted }
        all = s.items().filter { $0.fields.kind == .login }
    }

    func pick(_ id: String) {
        guard let item = session?.get(id: id) else { return }
        complete(item.fields.username, item.fields.password)
    }
}

struct ExtensionView: View {
    @EnvironmentObject var model: ExtensionModel
    @State private var password = ""
    @State private var query = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Group {
                if model.mode == .configured {
                    ContentUnavailableView {
                        Label("CleanPassword Is On", systemImage: "checkmark.circle")
                    } description: {
                        Text("Your logins will be offered when you sign in. Set up the vault in the CleanPassword app if you haven't yet.")
                    } actions: {
                        Button("Done") { model.cancel() }.buttonStyle(.borderedProminent)
                    }
                } else if model.info == nil {
                    ContentUnavailableView("No Vault Yet", systemImage: "key", description: Text("Open the CleanPassword app to set up your vault."))
                } else if !model.unlocked {
                    unlockForm
                } else {
                    list
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.cancel() } }
            }
        }
        .task {
            if model.mode == .list { await model.tryBiometrics() }
        }
    }

    private var unlockForm: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.tint)
            Text(model.site.isEmpty ? "Unlock CleanPassword" : "Unlock to sign in to \(model.site)").font(.headline)
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .padding(12)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 10))
                .onSubmit { Task { await unlock() } }
            if let e = model.error { Text(e).foregroundStyle(.red).font(.footnote) }
            Button {
                Task { await unlock() }
            } label: {
                Group { if busy { ProgressView() } else { Text("Unlock") } }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || busy)
            Spacer()
        }
        .padding(24)
    }

    private func unlock() async {
        busy = true
        await model.unlock(password: password)
        busy = false
    }

    private var list: some View {
        List {
            if query.isEmpty && !model.matches.isEmpty {
                Section("For \(model.site)") {
                    ForEach(model.matches) { m in
                        row(name: m.name, user: m.username, note: m.related ? "Shared sign-in" : nil) { model.pick(m.id) }
                    }
                }
            }
            Section(query.isEmpty ? "All Logins" : "Results") {
                ForEach(filtered) { i in
                    row(name: i.fields.name, user: i.fields.username, note: nil) { model.pick(i.id) }
                }
            }
        }
        .searchable(text: $query)
        .navigationTitle("Passwords")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var filtered: [VaultItem] {
        let words = query.lowercased().split(separator: " ")
        guard !words.isEmpty else { return model.all }
        return model.all.filter { i in
            let hay = ([i.fields.name, i.fields.username] + i.fields.websites.map(\.uri)).joined(separator: " ").lowercased()
            return words.allSatisfy { hay.contains($0) }
        }
    }

    private func row(name: String, user: String, note: String?, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading) {
                Text(name).foregroundStyle(.primary)
                Text([user.isEmpty ? "No user name" : user, note].compactMap { $0 }.joined(separator: " · ")).font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }
}
