import AuthenticationServices
import SwiftUI

/// The AutoFill extension: what iOS opens from the keyboard's "Passwords"
/// button, the suggestions above it, and Safari's and apps' sign-in sheets,
/// for passwords, passkeys and verification codes; and, from the "AutoFill
/// → Passwords" text menu in any field, any value of an item. It unlocks
/// the vault this device keeps (Face ID, or the master password), offers
/// what fits the site, and hands the chosen one to iOS; and it saves new
/// passkeys sites make, syncing them at once so the app and other devices
/// get them.
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

    private var askedBiometrics = false

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !askedBiometrics else { return }
        askedBiometrics = true
        Task { await model.tryBiometrics() }
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

    /// A verification-code field (iOS 18): the logins for the site that
    /// have a TOTP secret.
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.services = serviceIdentifiers.map(\.identifier)
        model.mode = .codes
    }

    #if !targetEnvironment(macCatalyst)
    /// "AutoFill → Passwords" from a field's text menu (iOS 18, not on the
    /// Mac): any value of any item, typed into the field.
    @available(iOS 18.0, *)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        model.mode = .text
    }
    #endif

    /// A suggestion above the keyboard was picked. The vault is locked
    /// whenever the extension starts, so this always needs the user (Face ID).
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    /// …so iOS shows the extension for it: unlock, then hand over that login,
    /// passkey or code.
    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if #available(iOS 18.0, *), let identity = credentialRequest.credentialIdentity as? ASOneTimeCodeCredentialIdentity {
            model.wantedCode = identity.recordIdentifier
            model.services = [identity.serviceIdentifier.identifier]
            model.mode = .codes
            return
        }
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
        // The account's passkeys the site already knows (iOS 18): if one of
        // them is here, the site has its passkey and none is made.
        if #available(iOS 18.0, *), let excluded = p.excludedCredentials {
            model.excluded = excluded.map(\.credentialID)
        }
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
    enum Mode { case list, codes, text, register, configured }

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

    /// One value of an item that can be typed into a field.
    struct Value: Identifiable {
        var label: String
        var text: String
        var hidden: Bool
        /// A verification code: made again when it's picked, as the one
        /// shown may have expired meanwhile.
        var codeOf: String?
        var id: String { label }
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
    var wantedCode: String?
    var wantedPasskey: (item: String, credential: Data)?
    var passkeyRequest: PasskeyRequest?
    var registration: Registration?
    var excluded: [Data] = []
    var context: () -> ASCredentialProviderExtensionContext? = { nil }
    private var session: VaultSession?

    var info: LockedVault? { SavedVault.load().flatMap { lockedVault(saved: $0) } }

    var site: String {
        guard let s = services.first else { return "" }
        return URL(string: s)?.host ?? s
    }

    func cancel() {
        fail(.userCanceled)
    }

    private func fail(_ code: ASExtensionError.Code) {
        context()?.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    /// Ends the screen shown when AutoFill is turned on in Settings.
    func finishConfiguration() {
        context()?.completeExtensionConfigurationRequest()
    }

    /// Face ID, once the sheet is on screen (the controller's viewDidAppear,
    /// or the Use Face ID button): asked any earlier, while iOS is still
    /// presenting the extension, it can fail without a prompt.
    func tryBiometrics() async {
        // Turning AutoFill on in Settings needs no unlocking.
        guard mode != .configured, !unlocked, !busy else { return }
        guard let saved = SavedVault.load(), let id = info?.vaultId, BiometricKey.exists(vaultId: id) else { return }
        busy = true
        defer { busy = false }
        let result = await Task.detached { BiometricKey.readKey(vaultId: id, reason: "Unlock CleanPassword") }.value
        switch result {
        case .failure(let e):
            // Cancelled (or the password chosen instead): no message.
            if e.code != Int(errSecUserCanceled) {
                error = "\(BiometricKey.biometryName) didn't unlock CleanPassword (error \(e.code)). Try again, or use your PIN or master password."
            }
        case .success(let key):
            do {
                let s = try await Task.detached { try VaultSession.unlockWithKey(saved: saved, key: key) }.value
                error = nil
                await opened(s, from: saved)
            } catch {
                self.error = message(error)
            }
        }
    }

    func unlock(password: String) async {
        guard let saved = SavedVault.load() else { return }
        do {
            let s = try await Task.detached { try VaultSession.unlock(saved: saved, password: password) }.value
            await opened(s, from: saved)
        } catch {
            self.error = message(error)
        }
    }

    var pinOn: Bool { info.map { PinKey.exists(vaultId: $0.vaultId) } ?? false }

    var biometricsOn: Bool { info.map { BiometricKey.exists(vaultId: $0.vaultId) } ?? false }

    /// Unlocks with the PIN set up in the app.
    func unlock(pin: String) async {
        guard let saved = SavedVault.load(), let id = info?.vaultId else { return }
        let outcome = await Task.detached { PinKey.unlock(pin: pin, vaultId: id) }.value
        guard case .key(let key) = outcome else {
            error = PinKey.explain(outcome)
            return
        }
        do {
            let s = try await Task.detached { try VaultSession.unlockWithKey(saved: saved, key: key) }.value
            await opened(s, from: saved)
        } catch {
            self.error = message(error)
        }
    }

    /// The saved vault as this extension opened or last wrote it: anything
    /// else on disk was saved by the app meanwhile, and is merged in.
    private var lastSaved: String?

    private func opened(_ s: VaultSession, from saved: String) async {
        session = s
        lastSaved = saved
        unlocked = true
        // The suggestions above the keyboard, in case iOS has none yet (the
        // app last registered them before AutoFill was turned on).
        SuggestionStore.update(with: s.items())
        var seen = Set<String>()
        let siteMatches = services.flatMap { s.matches(url: $0) }.filter { seen.insert($0.id).inserted }
        switch mode {
        case .codes:
            if let id = wantedCode { return pickCode(id) }
            let withCode = Set(s.items().filter { !$0.fields.totp.isEmpty }.map(\.id))
            matches = siteMatches.filter { withCode.contains($0.id) }
            all = s.items().filter { withCode.contains($0.id) }
        case .text:
            all = s.items()
        case .register:
            if let r = registration, !excluded.isEmpty, s.passkeyExcluded(rpId: r.rpId, excluded: excluded) {
                if #available(iOS 18.0, *) { return fail(.matchedExcludedCredential) }
                error = "You already have a passkey for this account on \(r.rpId)."
            }
            // Now, not as the form draws: after saving, a sync that's still
            // going holds the vault.
            if let r = registration { registrationLogins = s.siteLogins(url: r.rpId).filter { !$0.related } }
        case .list, .configured:
            if let w = wantedPasskey {
                return await usePasskey(item: w.item, credential: w.credential)
            }
            if let id = wanted, let item = s.get(id: id) {
                return complete(item)
            }
            if let r = passkeyRequest {
                passkeys = s.passkeysFor(rpId: r.rpId, allowed: r.allowed)
            }
            matches = siteMatches
            all = s.items().filter { $0.fields.kind == .login }
        }
    }

    func pick(_ id: String) {
        guard let item = session?.get(id: id) else { return }
        complete(item)
    }

    /// Fills a login; one with a verification code also puts its current
    /// code on the clipboard, for the site's next step (unless that's off).
    private func complete(_ item: VaultItem) {
        if Clipboard.copyCodeAfterFill, !item.fields.totp.isEmpty, let code = session?.totp(id: item.id) {
            copySecret(code.code)
        }
        complete(user: item.fields.username, password: item.fields.password)
    }

    private func complete(user: String, password: String) {
        context()?.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password), completionHandler: nil)
    }

    /// Fills the login's current verification code.
    func pickCode(_ id: String) {
        guard #available(iOS 18.0, *) else { return }
        guard let code = session?.totp(id: id) else {
            error = "This login's verification code setup isn't valid. Fix it in the CleanPassword app."
            return
        }
        context()?.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code.code), completionHandler: nil)
    }

    /// The values of an item that can be typed into a field, in the order
    /// the app shows them.
    func values(of item: VaultItem) -> [Value] {
        let f = item.fields
        var out: [Value] = []
        func add(_ label: String, _ text: String, hidden: Bool = false) {
            if !text.isEmpty { out.append(Value(label: label, text: text, hidden: hidden)) }
        }
        add("User Name", f.username)
        add("Password", f.password, hidden: true)
        if !f.totp.isEmpty, let code = session?.totp(id: item.id) {
            out.append(Value(label: "Verification Code", text: code.code, hidden: false, codeOf: item.id))
        }
        for (n, site) in f.websites.enumerated() { add(n == 0 ? "Website" : "Website \(n + 1)", site.uri) }
        for field in f.fields { add(field.name.isEmpty ? "Field" : field.name, field.value, hidden: field.hidden) }
        add("Notes", f.notes)
        // Labels are the rows' ids: keep the first of any repeated name.
        var seen = Set<String>()
        return out.filter { seen.insert($0.label).inserted }
    }

    /// Types the value into the field the menu was opened from.
    func insert(_ value: Value) {
        #if !targetEnvironment(macCatalyst)
        guard #available(iOS 18.0, *) else { return }
        let text = value.codeOf.flatMap { session?.totp(id: $0)?.code } ?? value.text
        context()?.completeRequest(withTextToInsert: text, completionHandler: nil)
        #endif
    }

    /// Saves the vault (merged with what the app saved meanwhile), so the
    /// change made here (a new passkey) is kept: throws if it can't be.
    /// Then registers the suggestions again, so a new passkey is offered
    /// above the keyboard at once, and syncs, so other devices get it even
    /// if the app doesn't run first; but waits for the sync only briefly,
    /// as the site is waiting too. A sync not done by then is left to the
    /// app (the change is saved, and uploaded on its next sync).
    private func saveAndSync(_ s: VaultSession) async throws {
        let before = lastSaved
        lastSaved = try await Task.detached { try SavedVault.write(s, lastSaved: before).text }.value
        SuggestionStore.update(with: s.items())
        if await Self.syncBriefly(s, seconds: 3) {
            let before = lastSaved
            if let text = try? await Task.detached(operation: { try SavedVault.write(s, lastSaved: before).text }).value {
                lastSaved = text
            }
        }
    }

    /// Syncs, waiting at most `seconds`. False if it failed or is still
    /// going (it then finishes in the background, and nothing more is saved
    /// here).
    private nonisolated static func syncBriefly(_ s: VaultSession, seconds: Double) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let lock = NSLock()
            var resumed = false
            let finish = { (ok: Bool) in
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                cont.resume(returning: ok)
            }
            DispatchQueue.global(qos: .userInitiated).async { finish((try? s.sync()) != nil) }
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { finish(false) }
        }
    }

    func usePasskey(item: String, credential: Data) async {
        guard let s = session, let r = passkeyRequest else { return }
        do {
            let sig = try s.assertPasskey(itemId: item, credentialId: credential, rpId: r.rpId, clientDataHash: r.clientDataHash)
            // A sign-in changes nothing that must be kept: it goes ahead
            // even if saving fails.
            if s.hasUnsyncedChanges() { try? await saveAndSync(s) }
            let answer = ASPasskeyAssertionCredential(
                userHandle: sig.userHandle, relyingParty: r.rpId, signature: sig.signature, clientDataHash: r.clientDataHash,
                authenticatorData: sig.authenticatorData, credentialID: sig.credentialId)
            context()?.completeAssertionRequest(using: answer, completionHandler: nil)
        } catch {
            self.error = message(error)
        }
    }

    /// A strong password for the site (following its known rules).
    func newPassword() -> String {
        site.isEmpty ? ((try? generatePassword(recipe: .apple)) ?? "") : generateForSite(host: site)
    }

    /// Signing up: saves a new login for the site (synced, so other
    /// devices have it), then fills it in.
    func createLogin(user: String, password: String) async {
        guard let s = session else { return }
        busy = true
        defer { busy = false }
        var f = ItemFields.empty()
        f.username = user.trimmingCharacters(in: .whitespaces)
        f.password = password
        if let service = services.first, !service.isEmpty {
            f.websites = [Website(uri: service.contains("://") ? service : "https://\(service)", matching: .default)]
        }
        do {
            _ = try s.add(fields: f)
            try await saveAndSync(s)
            complete(user: f.username, password: password)
        } catch {
            self.error = message(error)
        }
    }

    /// The logins a new passkey can go on.
    @Published var registrationLogins: [SuggestedLogin] = []

    func savePasskey(on itemId: String?) async {
        guard let s = session, let r = registration else { return }
        busy = true
        defer { busy = false }
        do {
            let reg = try s.createPasskey(rpId: r.rpId, rpName: "", userHandle: r.userHandle, userName: r.userName, userDisplayName: r.userName, itemId: itemId)
            // Only a passkey that's kept is handed to the site: if it can't
            // be saved, the site is told nothing was made.
            try await saveAndSync(s)
            let answer = ASPasskeyRegistrationCredential(relyingParty: r.rpId, clientDataHash: r.clientDataHash, credentialID: reg.credentialId, attestationObject: reg.attestationObject)
            context()?.completeRegistrationRequest(using: answer, completionHandler: nil)
        } catch {
            self.error = message(error)
        }
    }
}

/// Signing up on a site: a strong password, made for it, saved with the
/// user name typed here, and filled in.
struct NewLoginForm: View {
    @EnvironmentObject var model: ExtensionModel
    @State private var user = ""
    @State private var password = ""

    var body: some View {
        Form {
            Section {
                HStack {
                    TextField("User name or email", text: $user)
                        .textContentType(.username).textInputAutocapitalization(.never).autocorrectionDisabled()
                    UsernameMenu(username: $user)
                }
                HStack {
                    Text(password).font(.body.monospaced())
                    Spacer()
                    Button { password = model.newPassword() } label: { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Another Password")
                }
            } footer: {
                Text("A strong password for \(model.site.isEmpty ? "this app" : model.site), saved in CleanPassword on all your devices, and filled in.")
            }
            if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
            Section {
                Button {
                    Task { await model.createLogin(user: user, password: password) }
                } label: {
                    HStack { Text("Save and Fill"); Spacer(); if model.busy { ProgressView() } }
                }
                .disabled(model.busy || password.isEmpty)
            }
        }
        .navigationTitle("New Password")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if password.isEmpty { password = model.newPassword() } }
    }
}

struct ExtensionView: View {
    @EnvironmentObject var model: ExtensionModel
    @State private var password = ""
    @State private var query = ""
    @State private var busy = false
    @State private var target = ""
    @State private var usePin = false

    var body: some View {
        NavigationStack {
            Group {
                if model.mode == .configured {
                    ContentUnavailableView {
                        Label("CleanPassword Is On", systemImage: "checkmark.circle")
                    } description: {
                        Text("Your passwords, passkeys and verification codes will be offered when you sign in. Set up the vault in the CleanPassword app if you haven't yet.")
                    } actions: {
                        Button("Done") { model.finishConfiguration() }.buttonStyle(.borderedProminent)
                    }
                } else if model.info == nil {
                    ContentUnavailableView("No Vault Yet", systemImage: "key", description: Text("Open the CleanPassword app to set up your vault."))
                } else if !model.unlocked {
                    unlockForm
                } else {
                    switch model.mode {
                    case .register: registerForm
                    case .codes: codeList
                    case .text: textList
                    case .list, .configured: list
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.cancel() } }
            }
        }
    }

    private var unlockTitle: String {
        switch model.mode {
        case .codes where !model.site.isEmpty: return "Unlock to get a code for \(model.site)"
        case .text: return "Unlock CleanPassword"
        default: return model.site.isEmpty ? "Unlock CleanPassword" : "Unlock to sign in to \(model.site)"
        }
    }

    private var unlockIcon: String {
        if model.mode == .register || model.wantedPasskey != nil { return "person.badge.key.fill" }
        if model.mode == .codes { return "clock.badge.checkmark" }
        return "lock.fill"
    }

    private var unlockForm: some View {
        VStack(spacing: 16) {
            Image(systemName: unlockIcon).font(.largeTitle).foregroundStyle(.tint)
            Text(unlockTitle).font(.headline).multilineTextAlignment(.center)
            SecureField(usePin ? "PIN" : "Master password", text: $password)
                .textContentType(usePin ? .oneTimeCode : .password)
                .keyboardType(usePin ? .numberPad : .default)
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
            if model.pinOn || usePin {
                Button(usePin ? "Use Master Password" : "Use PIN") {
                    usePin.toggle()
                    password = ""
                    model.error = nil
                }
            }
            if model.biometricsOn && BiometricKey.isAvailable {
                Button {
                    Task { await model.tryBiometrics() }
                } label: {
                    Label("Use \(BiometricKey.biometryName)", systemImage: BiometricKey.symbol)
                }
                .disabled(model.busy)
            }
            if !model.biometricsOn && BiometricKey.isAvailable {
                Text("Turn on Unlock with \(BiometricKey.biometryName) in CleanPassword's Settings to skip the password here.")
                    .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding(24)
        // The PIN first, when it's set up.
        .onAppear { usePin = model.pinOn }
    }

    private func unlock() async {
        busy = true
        if usePin { await model.unlock(pin: password) } else { await model.unlock(password: password) }
        password = ""
        busy = false
        // Too many wrong PINs: back to the master password.
        if usePin && !model.pinOn { usePin = false }
    }

    /// "Save a passkey for … on …?", as in Apple's Passwords.
    private var registerForm: some View {
        Form {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "person.badge.key.fill").font(.system(size: 40)).foregroundStyle(.tint)
                    Text("Save a passkey for “\(model.registration?.userName ?? "")” on \(model.registration?.rpId ?? "")?")
                        .font(.headline).multilineTextAlignment(.center)
                    Text("You'll sign in with \(BiometricKey.biometryName) instead of a password. The passkey is kept in CleanPassword, encrypted, on all your devices.")
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
            if query.isEmpty {
                Section {
                    NavigationLink {
                        NewLoginForm()
                    } label: {
                        Label(model.site.isEmpty ? "New Password" : "New Password for \(model.site)", systemImage: "plus.circle")
                    }
                }
            }
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

    /// Verification codes: the site's logins with one first, then all.
    private var codeList: some View {
        List {
            if query.isEmpty && !model.matches.isEmpty {
                Section("Codes for \(model.site)") {
                    ForEach(model.matches) { m in
                        row(name: m.name, user: m.username, note: m.related ? "Shared sign-in" : nil) { model.pickCode(m.id) }
                    }
                }
            }
            Section(query.isEmpty ? "All Codes" : "Results") {
                ForEach(filtered) { i in
                    row(name: i.fields.name, user: i.fields.username, note: nil) { model.pickCode(i.id) }
                }
            }
            if model.all.isEmpty && model.error == nil {
                Text("None of your logins has a verification code. Add its setup key in the CleanPassword app.").foregroundStyle(.secondary)
            }
            if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
        }
        .searchable(text: $query)
        .navigationTitle("Verification Codes")
        .navigationBarTitleDisplayMode(.inline)
    }

    /// Any item, then the value of it to type into the field.
    private var textList: some View {
        List {
            Section(query.isEmpty ? "All Items" : "Results") {
                ForEach(filtered) { i in
                    NavigationLink {
                        valueList(i)
                    } label: {
                        VStack(alignment: .leading) {
                            Text(i.fields.name).foregroundStyle(.primary)
                            if !i.fields.username.isEmpty {
                                Text(i.fields.username).font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .searchable(text: $query)
        .navigationTitle("Insert From CleanPassword")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func valueList(_ item: VaultItem) -> some View {
        List {
            let values = model.values(of: item)
            if values.isEmpty {
                Text("This item has nothing to insert.").foregroundStyle(.secondary)
            }
            ForEach(values) { v in
                Button {
                    model.insert(v)
                } label: {
                    VStack(alignment: .leading) {
                        Text(v.label).font(.subheadline).foregroundStyle(.secondary)
                        Text(v.hidden ? String(repeating: "•", count: min(v.text.count, 12)) : v.text)
                            .foregroundStyle(.primary).lineLimit(3)
                    }
                }
            }
        }
        .navigationTitle(item.fields.name)
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
