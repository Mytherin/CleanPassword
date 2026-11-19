import AuthenticationServices
import SwiftUI

/// The AutoFill extension: what iOS opens from the keyboard's "Passwords"
/// button, the suggestions above it, and Safari's and apps' sign-in sheets,
/// for passwords and passkeys. It unlocks the vault this device keeps
/// (Face ID, or the master password), offers the logins and passkeys for
/// the site, and hands the chosen one to iOS; and it saves new passkeys
/// sites make, syncing them at once so the app and other devices get them.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let model = ExtensionModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        model.context = { [weak self] in self?.extensionContext }
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

    /// The same, when the page also accepts a passkey: those come first.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        model.services = serviceIdentifiers.map(\.identifier)
        model.passkeyRequest = ExtensionModel.PasskeyRequest(
            rpId: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash, allowed: requestParameters.allowedCredentials)
        model.mode = .list
    }

    /// A suggestion above the keyboard was picked. The vault is locked
    /// whenever the extension starts, so this always needs the user (Face ID).
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    /// …so iOS shows the extension for it: unlock, then hand over that login
    /// or passkey.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if let p = credentialRequest as? ASPasskeyCredentialRequest, let identity = p.credentialIdentity as? ASPasskeyCredentialIdentity {
            model.passkeyRequest = ExtensionModel.PasskeyRequest(rpId: identity.relyingPartyIdentifier, clientDataHash: p.clientDataHash, allowed: [identity.credentialID])
            model.wantedPasskey = (identity.recordIdentifier ?? "", identity.credentialID)
            model.services = [identity.relyingPartyIdentifier]
        } else {
            model.wanted = credentialRequest.credentialIdentity.recordIdentifier
            model.services = [credentialRequest.credentialIdentity.serviceIdentifier.identifier]
        }
        model.mode = .list
    }

    /// A site wants to save a new passkey.
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let p = registrationRequest as? ASPasskeyCredentialRequest, let identity = p.credentialIdentity as? ASPasskeyCredentialIdentity,
              p.supportedAlgorithms.contains(ASCOSEAlgorithmIdentifier.ES256)
        else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.failed.rawValue))
            return
        }
        model.registration = ExtensionModel.Registration(
            rpId: identity.relyingPartyIdentifier, userName: identity.userName, userHandle: identity.userHandle, clientDataHash: p.clientDataHash)
        model.services = [identity.relyingPartyIdentifier]
        model.mode = .register
    }

    /// Turned on in Settings: nothing to configure here.
    override func prepareInterfaceForExtensionConfiguration() {
        model.mode = .configured
    }
}

@MainActor
final class ExtensionModel: ObservableObject {
    enum Mode { case list, register, configured }

    struct PasskeyRequest {
        var rpId: String
        var clientDataHash: Data
        var allowed: [Data]
    }

    struct Registration {
        var rpId: String
        var userName: String
        var userHandle: Data
        var clientDataHash: Data
    }

    @Published var mode: Mode = .list
    @Published var unlocked = false
    @Published var matches: [SuggestedLogin] = []
    @Published var passkeys: [PasskeyOption] = []
    @Published var all: [VaultItem] = []
    @Published var error: String?
    @Published var busy = false
    var services: [String] = []
    var wanted: String?
    var wantedPasskey: (item: String, credential: Data)?
    var passkeyRequest: PasskeyRequest?
    var registration: Registration?
    var context: () -> ASCredentialProviderExtensionContext? = { nil }
    private var session: VaultSession?

    var info: LockedVault? { SavedVault.load().flatMap { lockedVault(saved: $0) } }

    var site: String {
        guard let s = services.first else { return "" }
        return URL(string: s)?.host ?? s
    }

    func cancel() {
        context()?.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }

    /// Ends the screen shown when AutoFill is turned on in Settings.
    func finishConfiguration() {
        context()?.completeExtensionConfigurationRequest()
    }

    func tryBiometrics() async {
        // Turning AutoFill on in Settings needs no unlocking.
        guard mode != .configured else { return }
        guard let saved = SavedVault.load(), let id = info?.vaultId, BiometricKey.exists(vaultId: id) else { return }
        let key = await Task.detached { BiometricKey.read(vaultId: id, reason: "Unlock CleanPassword") }.value
        guard let key, let s = try? VaultSession.unlockWithKey(saved: saved, key: key) else { return }
        await opened(s)
    }

    func unlock(password: String) async {
        guard let saved = SavedVault.load() else { return }
        do {
            let s = try await Task.detached { try VaultSession.unlock(saved: saved, password: password) }.value
            await opened(s)
        } catch {
            self.error = message(error)
        }
    }

    private func opened(_ s: VaultSession) async {
        session = s
        unlocked = true
        if let w = wantedPasskey {
            return await usePasskey(item: w.item, credential: w.credential)
        }
        if let id = wanted, let item = s.get(id: id) {
            return complete(user: item.fields.username, password: item.fields.password)
        }
        if let r = passkeyRequest {
            passkeys = s.passkeysFor(rpId: r.rpId, allowed: r.allowed)
        }
        var seen = Set<String>()
        matches = services.flatMap { s.matches(url: $0) }.filter { seen.insert($0.id).inserted }
        all = s.items().filter { $0.fields.kind == .login }
    }

    func pick(_ id: String) {
        guard let item = session?.get(id: id) else { return }
        complete(user: item.fields.username, password: item.fields.password)
    }

    private func complete(user: String, password: String) {
        context()?.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password), completionHandler: nil)
    }

    /// Saves the vault, and syncs it so a change made here (a new passkey,
    /// a counter) reaches the app and other devices even if the app doesn't
    /// run first.
    private func saveAndSync(_ s: VaultSession) async {
        let text = s.save()
        try? SavedVault.store(text)
        _ = try? await Task.detached { try s.sync() }.value
        try? SavedVault.store(s.save())
    }

    func usePasskey(item: String, credential: Data) async {
        guard let s = session, let r = passkeyRequest else { return }
        do {
            let sig = try s.assertPasskey(itemId: item, credentialId: credential, rpId: r.rpId, clientDataHash: r.clientDataHash)
            if s.hasUnsyncedChanges() { await saveAndSync(s) }
            let answer = ASPasskeyAssertionCredential(
                userHandle: sig.userHandle, relyingParty: r.rpId, signature: sig.signature, clientDataHash: r.clientDataHash,
                authenticatorData: sig.authenticatorData, credentialID: sig.credentialId)
            context()?.completeAssertionRequest(using: answer, completionHandler: nil)
        } catch {
            self.error = message(error)
        }
    }

    /// The logins a new passkey can go on.
    var registrationLogins: [SuggestedLogin] {
        guard let r = registration, let s = session else { return [] }
        return s.matches(url: r.rpId).filter { !$0.related }
    }

    func savePasskey(on itemId: String?) async {
        guard let s = session, let r = registration else { return }
        busy = true
        defer { busy = false }
        do {
            let reg = try s.createPasskey(rpId: r.rpId, rpName: "", userHandle: r.userHandle, userName: r.userName, userDisplayName: r.userName, itemId: itemId)
            await saveAndSync(s)
            let answer = ASPasskeyRegistrationCredential(relyingParty: r.rpId, clientDataHash: r.clientDataHash, credentialID: reg.credentialId, attestationObject: reg.attestationObject)
            context()?.completeRegistrationRequest(using: answer, completionHandler: nil)
        } catch {
            self.error = message(error)
        }
    }
}

struct ExtensionView: View {
    @EnvironmentObject var model: ExtensionModel
    @State private var password = ""
    @State private var query = ""
    @State private var busy = false
    @State private var target = ""

    var body: some View {
        NavigationStack {
            Group {
                if model.mode == .configured {
                    ContentUnavailableView {
                        Label("CleanPassword Is On", systemImage: "checkmark.circle")
                    } description: {
                        Text("Your passwords and passkeys will be offered when you sign in. Set up the vault in the CleanPassword app if you haven't yet.")
                    } actions: {
                        Button("Done") { model.finishConfiguration() }.buttonStyle(.borderedProminent)
                    }
                } else if model.info == nil {
                    ContentUnavailableView("No Vault Yet", systemImage: "key", description: Text("Open the CleanPassword app to set up your vault."))
                } else if !model.unlocked {
                    unlockForm
                } else if model.mode == .register {
                    registerForm
                } else {
                    list
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.cancel() } }
            }
        }
        .task { await model.tryBiometrics() }
    }

    private var unlockForm: some View {
        VStack(spacing: 16) {
            Image(systemName: model.mode == .register || model.wantedPasskey != nil ? "person.badge.key.fill" : "lock.fill").font(.largeTitle).foregroundStyle(.tint)
            Text(model.site.isEmpty ? "Unlock CleanPassword" : "Unlock to sign in to \(model.site)").font(.headline).multilineTextAlignment(.center)
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

    /// "Save a passkey for … on …?", as in Apple's Passwords.
    private var registerForm: some View {
        Form {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "person.badge.key.fill").font(.system(size: 40)).foregroundStyle(.tint)
                    Text("Save a passkey for “\(model.registration?.userName ?? "")” on \(model.registration?.rpId ?? "")?")
                        .font(.headline).multilineTextAlignment(.center)
                    Text("You'll sign in with Face ID instead of a password. The passkey is kept in CleanPassword, encrypted, on all your devices.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }
            if !model.registrationLogins.isEmpty {
                Section("Save On") {
                    Picker("Login", selection: $target) {
                        Text("A New Login").tag("")
                        ForEach(model.registrationLogins) { l in Text(l.username.isEmpty ? l.name : "\(l.name) (\(l.username))").tag(l.id) }
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                }
            }
            if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
            Section {
                Button {
                    Task { await model.savePasskey(on: target.isEmpty ? nil : target) }
                } label: {
                    HStack { Text("Save Passkey"); Spacer(); if model.busy { ProgressView() } }
                }
                .disabled(model.busy)
            }
        }
        .navigationTitle("Passkey")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            let user = model.registration?.userName.lowercased() ?? ""
            target = model.registrationLogins.first { !user.isEmpty && $0.username.lowercased() == user }?.id ?? ""
        }
    }

    private var list: some View {
        List {
            if query.isEmpty && !model.passkeys.isEmpty {
                Section("Passkeys for \(model.passkeyRequest?.rpId ?? model.site)") {
                    ForEach(model.passkeys, id: \.credentialId) { p in
                        Button {
                            Task { await model.usePasskey(item: p.itemId, credential: p.credentialId) }
                        } label: {
                            Label {
                                VStack(alignment: .leading) {
                                    Text(p.userName.isEmpty ? p.itemName : p.userName).foregroundStyle(.primary)
                                    Text("Passkey · \(p.itemName)").font(.subheadline).foregroundStyle(.secondary)
                                }
                            } icon: {
                                Image(systemName: "person.badge.key.fill")
                            }
                        }
                    }
                }
            }
            if query.isEmpty && !model.matches.isEmpty {
                Section("Passwords for \(model.site)") {
                    ForEach(model.matches) { m in
                        row(name: m.name, user: m.username, note: m.related ? "Shared sign-in" : nil) { model.pick(m.id) }
                    }
                }
            }
            Section(query.isEmpty ? "All Passwords" : "Results") {
                ForEach(filtered) { i in
                    row(name: i.fields.name, user: i.fields.username, note: nil) { model.pick(i.id) }
                }
            }
            if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
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
