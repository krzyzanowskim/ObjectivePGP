// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

// Generate new key
let key1 = KeyGenerator().generate(for: "marcin@krzyzanowskim.com", passphrase: nil)
let key2 = KeyGenerator().generate(for: "fran@krzyzanowskim.com", passphrase: nil)

let plaintext = Data(bytes: [1,2,3,4,5])

// Encrypt 5 bytes using selected key
let encryptedBin = try ObjectivePGP.encrypt(plaintext, addSignature: false, using: [key1, key2])
let encrypted = Armor.armored(encryptedBin, as: .message)
print(encrypted)

// Sign the encrypted binary
let signatureBin = try ObjectivePGP.sign(encryptedBin, detached: true, using: [key1])
let signature = Armor.armored(signatureBin, as: .signature)
print(signature)

try ObjectivePGP.verify(encryptedBin, withSignature: signatureBin, using: [key1])

let decrypted = try ObjectivePGP.decrypt(encryptedBin, andVerifySignature: false, using: [key1])
print("Decrypted : \(Array(decrypted))")
