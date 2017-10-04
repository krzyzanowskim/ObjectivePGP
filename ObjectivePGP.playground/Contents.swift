// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

let pgp = ObjectivePGP()

// Generate new key
let generator = KeyGenerator()
let newKey = generator.generate(for: "marcin@krzyzanowskim.com", passphrase: nil)

// import key
pgp.import(keys: [newKey])
guard let key = pgp.findKey(newKey.keyID.shortIdentifier) else { fatalError("Can't find the key") }

// Encrypt 5 bytes using selected key
let encryptedArmoredData = try! pgp.encrypt(data: Data(bytes: [1,2,3,4,5]), using: [key], armored: true)
let encryptedAscii = String(data: encryptedArmoredData, encoding: .utf8)

print(encryptedAscii ?? "Missing")
