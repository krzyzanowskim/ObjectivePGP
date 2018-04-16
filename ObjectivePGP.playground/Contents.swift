// Build ObjectivePGP target first.
import ObjectivePGP
import Foundation

// Generate new key
let key1 = KeyGenerator().generate(for: "marcin@krzyzanowskim.com", passphrase: nil)
let key2 = KeyGenerator().generate(for: "fran@krzyzanowskim.com", passphrase: nil)

let plaintext = Data(bytes: [1,2,3,4,5])

// Encrypt 5 bytes using selected key

if let pkData = try? key2.export(keyType: .public), let pk = try? ObjectivePGP.readKeys(from: pkData){
    var keys = pk
    keys.append(key1)
    _ = try ObjectivePGP.encrypt(plaintext, addSignature: false, using: keys)
    do{
        _ = try ObjectivePGP.encrypt(plaintext, addSignature: true, using: keys)
    } catch{
        print(error)
    }
}
