// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

// Generate new key
let key1 = KeyGenerator().generate(for: "marcin@krzyzanowskim.com", passphrase: nil)
let key2 = KeyGenerator().generate(for: "fran@krzyzanowskim.com", passphrase: nil)

// Encrypt 5 bytes using selected key
let encrypted = try ObjectivePGP.encrypt(Data(bytes: [1,2,3,4,5]), addSignature:false, using: [key1, key2], passphraseForKey:nil)
let armored = Armor.armored(encrypted, as: PGPArmorType.typeMessage)

print(armored)
