![objectivepgp](https://user-images.githubusercontent.com/758033/27697465-a355ca34-5cf4-11e7-9470-ee1ee98eedd9.png)

[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/ObjectivePGP.svg)](https://cocoapods.org/pods/ObjectivePGP)
[![Platform](https://img.shields.io/cocoapods/p/ObjectivePGP.svg?style=flat)](http://cocoadocs.org/docsets/ObjectivePGP)
[![Swift](https://img.shields.io/badge/swift-supported-brightgreen.svg?style=flat)](./ObjectivePGP.playground/Contents.swift)
[![Twitter](https://img.shields.io/badge/twitter-@krzyzanowskim-blue.svg?style=flat)](http://twitter.com/krzyzanowskim)


**ObjectivePGP** is an implementation of [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol for iOS and macOS. OpenPGP is the most widely used email encryption standard. It is defined by the OpenPGP Working Group of the Internet Engineering Task Force (IETF).

Here is the [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) story.

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

## Contribution

You are welcome to contribute. Please create [Pull Request](https://github.com/krzyzanowskim/ObjectivePGP/pulls) against `develop` branch.

## Usage

##### Import module

```objective-c
#import <ObjectivePGP/ObjectivePGP.h>
```

```swift
import ObjectivePGP
```

##### Load keys (private or public)

```objective-c
NSArray<PGPKey *> *keys = [ObjectivePGP readKeysFromPath:@"/path/to/key.asc" error:nil];
```

```swift
let keys = try ObjectivePGP.readKeys(fromPath: "/path/to/key.asc")
```

##### ASCII Armor

ASCII armor is a binary-to-textual encoding converter. ASCII armor involves encasing encrypted messaging in ASCII so that they can be sent in a standard messaging format such as email.

Example:
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: For info see http://www.objectivepgp.org

[...]
-----END PGP PUBLIC KEY BLOCK-----
```

Class `PGPArmor` can be used to convert binary format to ASCII format
```objc
NSString *armoredKey = [PGPArmor armoredData:encrypted as:PGPArmorTypePublicKey];
```

```swift
let armoredKey = Armor.armored(Data(), as: .typePublicKey)
```

When convert manually, it is important to use right `PGPArmorType` value that define the header. It may be a tricky part so here's the cheatsheet:

| Type data  | PGPArmorType          | Example |
| ---------- | --------------------- |-------- |
| Encrypted  | `PGPArmorTypeMessage` | `Armor.armored(ObjectivePGP.encrypt(...), as: .typeMessage)` |
| Decrypted  | `PGPArmorTypeMessage` | `Armor.armored(ObjectivePGP.decrypt(...), as: .typeMessage)` |
| Pubic key  | `PGPArmorTypePublic`  | `Armor.armored(key.export(), as: .public)` |
| Secret key | `PGPArmorTypeSecret`  | `Armor.armored(key.export(), as: .secret)` |

For any result of encryption the type is `PGPArmorTypeMessage`

##### Keyring

Keyring is a storage (in memory or on disk) that keep all sorts of PGP keys.

```objc
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

```objc
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

##### Sign data (or file)

```objective-c
/* Choose a key to use to sign the data */
PGPKey *key = [keyring findKeyWithIdentifier:@"979E4B03DFFE30C6"];

// File to encrypt
NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];

/* Sign and return only a signature data (detached = YES) */
NSData *signature = [ObjectivePGP sign:fileContent usingKey:key passphrase:nil detached:YES error:nil];

/* Sign and return a data with the signature (detached = NO) */
NSData *signedData = [ObjectivePGP sign:fileContent usingSecretKey:key passphrase:nil detached:NO error:nil];
```

##### Verify signature from data (or file)

```objective-c
/* embedded signature */
NSData *signedContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.signed"];
if ([pgp verify:signedContent error:nil]) {
    // Success
}

/* detached signature */
NSData *signatureContent = [NSData dataWithContentsOfFile:@"/path/file/to/signature"];
NSData *dataContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];
if ([pgp verify:dataContent withSignature:signatureContent error:nil]) {
    // Success
}
```

##### Encrypt data with previously loaded public key

```
NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/plaintext.txt"];

/* Choose the public key to use to encrypt data. Must be imported previously */
PGPKey *key = [keyring findKeyWithIdentifier:@"979E4B03DFFE30C6"];

/* Encrypt data. Armor output (ASCII file)  */
NSData *encryptedData = [ObjectivePGP encrypt:fileContent usingKeys:@[key] armored:YES error:nil];
if (encryptedData) {
    // Success
}
```

##### Decrypt data with previously loaded private key
    
```objective-c
NSData *encryptedFileContent = [NSData dataWithContentsOfFile:@"/path/data.enc"];

/* If key is encrypted with the passphrase, you can provide a passphrase key here. */
NSData *decryptedData = [pgp decrypt:encryptedFileContent passphrase:nil error:nil];
if (decryptedData) {
    // Success
}
```

##### Generate new key

```objective-c
PGPKeyGenerator *generator = [[PGPKeyGenerator alloc] init];
PGPKey *key = [generator generateFor:@"Marcin <marcin@example.com>" passphrase:nil];
NSData *publicKeyData = [key export:PGPKeyTypePublic error:nil];
NSData *secretKeyData = [key export:PGPKeyTypeSecret error:nil];
```

## Changelog

See [CHANGELOG](./CHANGELOG)

Known limitations:

- Elgamal cipher is not supported.

## The license

The ObjectivePGP stays under a dual license:

- Free for non-commercial use, covered by the standard 2-clause BSD license. That means you have to mention Marcin Krzyżanowski as the original author of this code and reproduce the [LICENSE](./LICENSE.txt) text inside your app.

- Commercial-use license to use in commercial products. Please bear in mind that some free products remain commercial products. Please contact me via [email](http://www.krzyzanowskim.com) for details.

Not sure what to choose? check this [thread](https://twitter.com/krzyzanowskim/status/868481597204508672)

### Acknowledgment

This product uses software developed by the [OpenSSL](http://www.openssl.org/) Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

### Author

[Marcin Krzyżanowski](http://krzyzanowskim.com)
