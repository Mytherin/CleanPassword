import SwiftUI

/// Generated user names, as Bitwarden offers them: a menu beside a user
/// name field with a random word, your email with a random tag (each site
/// gets its own address, and mail still arrives), or a random name at a
/// domain of yours that takes every address. The email and domain are
/// asked for once and remembered (in the app group, for the AutoFill
/// extension too).
struct UsernameMenu: View {
    @Binding var username: String
    @AppStorage("usernameEmail", store: UserDefaults(suiteName: AppGroup.id)) private var email = ""
    @AppStorage("usernameDomain", store: UserDefaults(suiteName: AppGroup.id)) private var domain = ""
    @State private var asking: Ask?
    @State private var entry = ""

    enum Ask { case email, domain }

    var body: some View {
        Menu {
            Button { make(.word(capitalize: false, number: true)) } label: { Label("Random Word", systemImage: "textformat.abc") }
            Button {
                if email.isEmpty { ask(.email) } else { make(.plusAddress(email: email)) }
            } label: {
                Label(email.isEmpty ? "Email with a Random Tag…" : "\(email), Tagged", systemImage: "envelope")
            }
            Button {
                if domain.isEmpty { ask(.domain) } else { make(.catchAll(domain: domain)) }
            } label: {
                Label(domain.isEmpty ? "Random Name at Your Domain…" : "Random Name at \(domain)", systemImage: "at")
            }
            if !email.isEmpty || !domain.isEmpty {
                Divider()
                Button("Change Email or Domain…") {
                    email = ""
                    domain = ""
                }
            }
        } label: {
            Image(systemName: "person.badge.plus")
        }
        .accessibilityLabel("Generate User Name")
        .alert(asking == .email ? "Your Email Address" : "Your Domain", isPresented: Binding(get: { asking != nil }, set: { if !$0 { asking = nil } })) {
            TextField(asking == .email ? "name@example.com" : "example.com", text: $entry)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(asking == .email ? .emailAddress : .URL)
            Button("Cancel", role: .cancel) {}
            Button("Use") {
                let value = entry.trimmingCharacters(in: .whitespaces)
                if asking == .email {
                    if make(.plusAddress(email: value)) { email = value }
                } else if make(.catchAll(domain: value)) {
                    domain = value
                }
            }
        } message: {
            Text(asking == .email
                ? "Each site gets your address with a random tag (name+tag@example.com). Most email services deliver these to you."
                : "Each site gets a random name at this domain. Your domain's email must accept every address (a catch-all).")
        }
    }

    private func ask(_ what: Ask) {
        entry = ""
        asking = what
    }

    @discardableResult
    private func make(_ recipe: UsernameRecipe) -> Bool {
        guard let name = try? generateUsername(recipe: recipe) else { return false }
        username = name
        return true
    }
}
