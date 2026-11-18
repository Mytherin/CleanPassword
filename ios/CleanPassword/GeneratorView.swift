import SwiftUI

struct GeneratorView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("recipe") private var recipeData = Data()
    @State private var kind = 0
    @State private var length = 20.0
    @State private var lowercase = true
    @State private var uppercase = true
    @State private var digits = true
    @State private var symbols = true
    @State private var avoidAmbiguous = false
    @State private var words = 5.0
    @State private var capitalize = false
    @State private var number = true
    @State private var password = ""
    @State private var copied = false

    /// The recipe saved in settings (Apple-style if none).
    static func savedRecipe(_ data: Data) -> PasswordRecipe {
        guard let r = try? JSONDecoder().decode(StoredRecipe.self, from: data) else { return .apple }
        return r.recipe
    }

    var body: some View {
        Form {
            Section {
                Text(password)
                    .font(.title3.monospaced())
                    .frame(maxWidth: .infinity, alignment: .center)
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
                    .padding(.vertical, 8)
                HStack {
                    Button("Regenerate") { generate() }
                    Spacer()
                    Button(copied ? "Copied" : "Copy") {
                        copySecret(password)
                        copied = true
                    }
                }
                .buttonStyle(.borderless)
            }
            Section {
                Picker("Kind", selection: $kind) {
                    Text("Apple-style").tag(0)
                    Text("Random").tag(1)
                    Text("Words").tag(2)
                }
                .pickerStyle(.segmented)
                switch kind {
                case 1:
                    Stepper("Length \(Int(length))", value: $length, in: 8...64)
                    Toggle("a–z", isOn: $lowercase)
                    Toggle("A–Z", isOn: $uppercase)
                    Toggle("0–9", isOn: $digits)
                    Toggle("!@#$…", isOn: $symbols)
                    Toggle("Avoid look-alikes", isOn: $avoidAmbiguous)
                case 2:
                    Stepper("\(Int(words)) words", value: $words, in: 3...10)
                    Toggle("Capitalize", isOn: $capitalize)
                    Toggle("Add a number", isOn: $number)
                default:
                    Text("Like Safari's: three groups of six letters with one capital and one digit. Easy to type, about 71 bits, accepted almost everywhere.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Generator")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { Button("Done") { dismiss() } }
        .onAppear(perform: load)
        .onChange(of: recipe) { _, _ in
            if let data = try? JSONEncoder().encode(StoredRecipe(recipe: recipe)) { recipeData = data }
            generate()
        }
    }

    private var recipe: PasswordRecipe {
        switch kind {
        case 1: return .random(length: UInt32(length), lowercase: lowercase, uppercase: uppercase, digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous)
        case 2: return .passphrase(words: UInt32(words), separator: "-", capitalize: capitalize, number: number)
        default: return .apple
        }
    }

    private func load() {
        switch Self.savedRecipe(recipeData) {
        case .apple:
            kind = 0
        case let .random(l, lo, up, d, s, a):
            kind = 1
            length = Double(l)
            lowercase = lo
            uppercase = up
            digits = d
            symbols = s
            avoidAmbiguous = a
        case let .passphrase(w, _, c, n):
            kind = 2
            words = Double(w)
            capitalize = c
            number = n
        }
        generate()
    }

    private func generate() {
        copied = false
        password = (try? generatePassword(recipe: recipe)) ?? "Choose at least one kind of character"
    }
}

/// A recipe as kept in settings.
struct StoredRecipe: Codable {
    var kind: Int
    var length = 20
    var lowercase = true, uppercase = true, digits = true, symbols = true, avoidAmbiguous = false
    var words = 5
    var capitalize = false, number = true

    init(recipe: PasswordRecipe) {
        switch recipe {
        case .apple: kind = 0
        case let .random(l, lo, up, d, s, a):
            kind = 1
            length = Int(l)
            lowercase = lo
            uppercase = up
            digits = d
            symbols = s
            avoidAmbiguous = a
        case let .passphrase(w, _, c, n):
            kind = 2
            words = Int(w)
            capitalize = c
            number = n
        }
    }

    var recipe: PasswordRecipe {
        switch kind {
        case 1: return .random(length: UInt32(length), lowercase: lowercase, uppercase: uppercase, digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous)
        case 2: return .passphrase(words: UInt32(words), separator: "-", capitalize: capitalize, number: number)
        default: return .apple
        }
    }
}
