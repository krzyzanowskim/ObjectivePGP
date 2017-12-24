![objectivepgp](https://user-images.githubusercontent.com/758033/27697465-a355ca34-5cf4-11e7-9470-ee1ee98eedd9.png)

[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/ObjectivePGP.svg)](https://cocoapods.org/pods/ObjectivePGP)
[![Platform](https://img.shields.io/cocoapods/p/ObjectivePGP.svg?style=flat)](http://cocoadocs.org/docsets/ObjectivePGP)
[![Swift](https://img.shields.io/badge/swift-supported-brightgreen.svg?style=flat)](./ObjectivePGP.playground/Contents.swift)
[![Twitter](https://img.shields.io/badge/twitter-@krzyzanowskim-blue.svg?style=flat)](http://twitter.com/krzyzanowskim)


**ObjectivePGP** is an implementation of [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol for iOS and macOS. OpenPGP is the most widely used email encryption standard. It is defined by the OpenPGP Working Group of the Internet Engineering Task Force (IETF).

Here is the [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) story.

## Contribution

You are welcome to contribute. Please create [Pull Request](https://github.com/krzyzanowskim/ObjectivePGP/pulls) against `develop` branch.

## Usage

```objective-c
#import <ObjectivePGP/ObjectivePGP.h>
```

```swift
import ObjectivePGP
```

##### Read keys (private or public)

```objective-c
NSArray<PGPKey *> *keys = [ObjectivePGP readKeysFromPath:@"/path/to/key.asc" error:nil];
```

```swift
let keys = try ObjectivePGP.readKeys(fromPath: "/path/to/key.asc")
```

##### Keyring

Keyring is a storage (in memory or on disk) that keep all sorts of PGP keys.

```objective-c
PGPKeyring *keyring = ObjectivePGP.defaultKeyring;
PGPKeyring *keyring = [[PGPKeyring alloc] init];

NSArray<PGPKey *> *allKeys = keyring.keys;
[keyring importKeys:@[key]];
[keyring deleteKeys:@[key]];

[keyring importKey:@"979E4B03DFFE30C6" fromPath:@"/path/to/secring.gpg"];
PGPKey *key = [keyring findKeyWithIdentifier:@"979E4B03DFFE30C6"];
NSArray<PGPKey *> keys = [pgp findKeysForUserID:@"Name <email@example.com>"];
```

```swift
let keyring = ObjectivePGP.defaultKeyring
let keyring = Keyring()

let allKeys = keyring.keys
keyring.import(keys: [key])
keyring.delete(keys: [key])

keyring.import(keyIdentifier:"979E4B03DFFE30C6", fromPath:"/path/to/secring.gpg")
if let key = keyring.findKey("979E4B03DFFE30C6") {
	// key found in keyring
}

keyring.findKeys("Name <email@example.com>").forEach(key) {
	// process key
}
```

##### Export keys (private or public)

```objective-c
// Write keyring to file
[[keyring export:error] writeToURL:[NSURL fileURLWithString:@"keyring.gpg"]];

// Public keys data
NSData *publicKeys = [keyring exportKeysOfType:PGPKeyTypePublic error:nil];
```

```swift
// Write keyring to file
try keyring.export().write(to: URL(fileURLWithPath: "keyring.gpg"))

// Public keys (Data)
let publicKeys = keyring.exportKeys(of: .public)
```

##### Sign & verify data (or file)

Sign a data with a key:

```objective-c
NSData *signature = [ObjectivePGP sign:fileContent detached:YES usingKeys:@[key] passphraseForKey:nil error:nil];
[ObjectivePGP verify:fileContent withSignature:signature usingKeys:@[key] passphraseForKey:nil error:nil];
```

```swift
let signature = try ObjectivePGP.sign(encryptedBin, detached:true, using: [key1])
try ObjectivePGP.verify(encryptedBin, withSignature: signature, using: [key1])
```

##### Encrypt & Decrypt

```objective-c
NSData *encrypted = [ObjectivePGP encrypt:fileContent addSignature:YES usingKeys:@[key] passphraseForKey:nil error:nil];
[ObjectivePGP decrypt:encrypted andVerifySignature:YES usingKeys:@[key] passphraseForKey:nil error:nil];
```

```swift
let encrypted = try ObjectivePGP.encrypt(fileContent), addSignature: true, using: [key1, key2])
let decrypted = try ObjectivePGP.decrypt(encrypted, andVerifySignature: true, using: [key1])
```

##### Generate new key pair

```objective-c
PGPKeyGenerator *generator = [[PGPKeyGenerator alloc] init];
PGPKey *key = [generator generateFor:@"Marcin <marcin@example.com>" passphrase:nil];
NSData *publicKeyData = [key export:PGPKeyTypePublic error:nil];
NSData *secretKeyData = [key export:PGPKeyTypeSecret error:nil];
```

```swift
let key = KeyGenerator().generate(for: "marcin@example.com", passphrase: "password")
let publicKey = try key.export(keyType: .public)
let secretKey = try key.export(keyType: .secret)
```

#### ASCII Armor

ASCII armor is a binary-to-textual encoding converter. ASCII armor involves encasing encrypted messaging in ASCII so that they can be sent in a standard messaging format such as email.

Example:
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: For info see http://www.objectivepgp.org

[...]
-----END PGP PUBLIC KEY BLOCK-----
```

Class `PGPArmor` can be used to convert binary format to ASCII format

```objective-c
NSString *armoredKey = [PGPArmor armoredData:encrypted as:PGPArmorPublicKey];
```

```swift
let armoredKey = Armor.armored(Data(), as: .publicKey)
```

When convert manually, it is important to use right `PGPArmorType` value that define the header. It may be a tricky part so here's the cheatsheet:

| Type data  | PGPArmorType          | Example |
| ---------- | --------------------- |-------- |
| Encrypted  | `PGPArmorMessage` | `Armor.armored(ObjectivePGP.encrypt(...), as: .message)` |
| Decrypted  | `PGPArmorMessage` | `Armor.armored(ObjectivePGP.decrypt(...), as: .message)` |
| Pubic key  | `PGPArmorTypePublic`  | `Armor.armored(key.export(), as: .publicKey)` |
| Secret key | `PGPArmorTypeSecret`  | `Armor.armored(key.export(), as: .secretKey)` |

For any result of encryption the type is `PGPArmorMessage`

## Installation

#### [CocoaPods](https://cocoapods.org/pods/ObjectivePGP)

```ruby
target 'TargetName' do
    use_frameworks!
    pod 'ObjectivePGP'
end
```

#### ObjectivePGP.framework

ObjectivePGP comes with the [Frameworks](./Frameworks) for the latest release.

1. Download latest [ObjectivePGP.framework](https://github.com/krzyzanowskim/ObjectivePGP/releases) or build a framework with the [build-frameworks.sh](./build-frameworks.sh) script.
1. Link framework with the target
    - Add `ObjectivePGP.framework` to "**Link Binary With Libraries**" list for the target.
    ![screen shot 2017-06-30 at 02 20 47](https://user-images.githubusercontent.com/758033/27715926-d79a4e3c-5d3a-11e7-8b1b-d8b5ddb8182e.png)
1. Link libraries and frameworks
    1. Add `Security.framework` to "**Link Binary With Libraries**" list for the target. These are system libraries.
    1. Add `libz` and `libbz2` to "**Link Binary With Libraries**" list for the target. These are system libraries.
1. In the Build Phases tab, click the + button at the top and select “New Run Script Phase”. Enter the following code into the script text field:

```sh
bash "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}/ObjectivePGP.framework/strip-frameworks.sh"
```

(The last step, is required for working around an iOS App Store bug when archiving universal binaries.)

## Changelog

See [CHANGELOG](./CHANGELOG)

Known limitations:

- Elgamal cipher is not supported.
- Cleartext signature.

## The license

The ObjectivePGP stays under a dual license:

- Free for non-commercial use, covered by the standard 2-clause BSD license. That means you have to mention Marcin Krzyżanowski as the original author of this code and reproduce the [LICENSE](./LICENSE.txt) text inside your app.

- Commercial-use license to use in commercial products. Please bear in mind that some free products remain commercial products. Please contact me via [email](http://www.krzyzanowskim.com) for details.

Not sure what to choose? check this [thread](https://twitter.com/krzyzanowskim/status/868481597204508672)

### Acknowledgment

This product uses software developed by the [OpenSSL](http://www.openssl.org/) Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

### Author

[Marcin Krzyżanowski](http://krzyzanowskim.com)
