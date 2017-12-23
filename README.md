![objectivepgp](https://user-images.githubusercontent.com/758033/27697465-a355ca34-5cf4-11e7-9470-ee1ee98eedd9.png)

[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/ObjectivePGP.svg)](https://cocoapods.org/pods/ObjectivePGP)
[![Platform](https://img.shields.io/cocoapods/p/ObjectivePGP.svg?style=flat)](http://cocoadocs.org/docsets/ObjectivePGP)
[![Swift](https://img.shields.io/badge/swift-supported-brightgreen.svg?style=flat)](./ObjectivePGP.playground/Contents.swift)
[![Twitter](https://img.shields.io/badge/twitter-@krzyzanowskim-blue.svg?style=flat)](http://twitter.com/krzyzanowskim)


**ObjectivePGP** is an implementation of [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol for iOS and macOS. OpenPGP is the most widely used email encryption standard. It is defined by the OpenPGP Working Group of the Internet Engineering Task Force (IETF).

Here is the [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) story.

## Installation

### CocoaPods

```ruby
target 'MyTargetName' do
    use_frameworks!
    pod 'ObjectivePGP'
end
```

### Dynamic framework

ObjectivePGP comes with the [Frameworks](./Frameworks) for the latest release.

1. Download [ObjectivePGP.framework](https://github.com/krzyzanowskim/ObjectivePGP/releases) or build a framework with the [build-frameworks.sh](./build-frameworks.sh) script.
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

##### Initialization

```objective-c
#import <ObjectivePGP/ObjectivePGP.h>

ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
```

##### Load keys (private or public)

```objective-c
/* Load keys from a keyring file */
NSArray *keys = [ObjectivePGP readKeysFromFile:@"/path/to/secring.gpg"];

/* Load eys from a keys file */
NSArray *keys = [ObjectivePGP readKeysFromFile:@"/path/to/key.asc"];

/* Import keys */
[pgp importKeys:keys];

/* Import selected key from a keyring */
[pgp importKey:@"979E4B03DFFE30C6" fromFile:@"/path/to/secring.gpg"];

```

##### Search for keys

```objective-c
/* long identifier 979E4B03DFFE30C6 */
PGPKey *key = [pgp findKeyWithIdentifier:@"979E4B03DFFE30C6"];

/* Short identifier 979E4B03 (the same result as previous) */
PGPKey *key = [pgp findKeyWithIdentifier:@"979E4B03"];

/* First key that match given user identifier string. */
PGPKey *key = [pgp findKeysForUserID:@"Name <email@example.com>"];
```

##### Export keys (private or public)

```objective-c
/* Export all public keys to file */
if ([pgp exportKeysOfType:PGPKeyTypePublic toFile:@"pubring.gpg" error:nil]) {
    // success
}

/* Export a key and save as armored (ASCII) file */
PGPKey *key = [keyring findKeyWithIdentifier:@"979E4B03DFFE30C6"];
NSData *armoredKeyData = [pgp exportKey:key armored:YES];
[armoredKeyData writeToFile:@"pubkey.asc" atomically:YES];
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
