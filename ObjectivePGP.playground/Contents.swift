// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

guard let keyURL = Bundle.main.url(forResource: "marcin.krzyzanowski@gmail.com", withExtension: "asc"),
      let keyData = try? Data(contentsOf: keyURL) else { fatalError("Can't find key file") }

let pgp = ObjectivePGP()
pgp.importKeys(from: keyData)
guard let key = pgp.findKey(forIdentifier: "878ECFB866753341") else { fatalError("Can't find the key") }

// Encrypt 5 bytes using selected key
let encryptedArmoredData = try! pgp.encryptData(Data(bytes: [1,2,3,4,5]), using: [key], armored: true)
let encryptedAscii = String(data: encryptedArmoredData, encoding: .utf8)

print(encryptedAscii ?? "Missing")
