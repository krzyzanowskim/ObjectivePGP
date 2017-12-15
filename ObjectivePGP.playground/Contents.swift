// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

// Generate new key
let key1 = KeyGenerator().generate(for: "marcin@krzyzanowskim.com", passphrase: nil)
let key2 = KeyGenerator().generate(for: "fran@krzyzanowskim.com", passphrase: nil)

// Encrypt 5 bytes using selected key
let encryptedArmoredData = try ObjectivePGP.encrypt(Data(bytes: [1,2,3,4,5]), using: [key1, key2], passphraseForKey:nil, armored: true)
let encryptedAscii = String(data: encryptedArmoredData, encoding: .utf8)

print(encryptedAscii ?? "Missing")
