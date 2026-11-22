import SwiftUI

/// An `otpauth://` link opened in the app (a verification-code QR code
/// scanned with the Camera app, or a link in Safari), as in Apple's
/// Passwords: choose the login to set it up on, or make a new one.
struct SetUpCodeView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    let link: String
    @State private var search: String
    @State private var replacing: VaultItem?
    @State private var error: String?

    init(link: String) {
        self.link = link
        _search = State(initialValue: CodeScannerView.label(of: link).issuer ?? "")
    }

    private var label: (issuer: String?, account: String?) { CodeScannerView.label(of: link) }

    var body: some View {
        let logins = SortOrder.title.sorted(store.items.filter { $0.fields.kind == .login && $0.matches(search: search) })
        List {
            Section {
                Button {
                    var f = ItemFields.empty()
                    f.totp = link
                    f.name = label.issuer ?? ""
                    f.username = label.account ?? ""
                    let draft = VaultStore.Draft(itemId: nil, original: .empty(), edited: f)
                    dismiss()
                    // The editor opens once this sheet has gone.
                    Task {
                        try? await Task.sleep(for: .milliseconds(400))
                        store.reopenDraft = draft
                    }
                } label: {
                    Label("New Password", systemImage: "plus")
                }
            } footer: {
                Text("Choose the password for \(label.issuer ?? "this site")\(label.account.map { " (\($0))" } ?? "") to keep its verification codes with it.")
            }
            Section(search.isEmpty ? "All Passwords" : "Results") {
                ForEach(logins) { i in
                    Button {
                        if i.fields.totp.isEmpty { setUp(on: i) } else { replacing = i }
                    } label: {
                        HStack {
                            ItemRow(item: i).foregroundStyle(.primary)
                            Spacer()
                            if !i.fields.totp.isEmpty { Image(systemName: "lock.rotation").foregroundStyle(.secondary) }
                        }
                    }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always))
        .navigationTitle("Set Up Verification Code")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
        }
        .confirmationDialog("Replace the verification code of “\(replacing?.fields.name ?? "")”?", isPresented: Binding(get: { replacing != nil }, set: { if !$0 { replacing = nil } }), titleVisibility: .visible) {
            Button("Replace", role: .destructive) {
                if let i = replacing { setUp(on: i) }
                replacing = nil
            }
        } message: {
            Text("Its current codes stop working on the site once you finish setting up the new one there.")
        }
    }

    private func setUp(on item: VaultItem) {
        Task {
            do {
                try await store.change { s in
                    guard var f = s.get(id: item.id)?.fields else { return }
                    f.totp = link
                    _ = try s.update(id: item.id, fields: f)
                }
                dismiss()
            } catch {
                self.error = message(error)
            }
        }
    }
}
