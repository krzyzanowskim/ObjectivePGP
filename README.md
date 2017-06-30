![objectivepgp](https://user-images.githubusercontent.com/758033/27697465-a355ca34-5cf4-11e7-9470-ee1ee98eedd9.png)

[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/ObjectivePGP.svg)](https://cocoapods.org/pods/ObjectivePGP)
[![Platform](https://img.shields.io/cocoapods/p/ObjectivePGP.svg?style=flat)](http://cocoadocs.org/docsets/ObjectivePGP)
[![Twitter](https://img.shields.io/badge/twitter-@krzyzanowskim-blue.svg?style=flat)](http://twitter.com/krzyzanowskim)


**ObjectivePGP** is an implementation of [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) protocol for iOS and macOS. OpenPGP is the most widely used email encryption standard. It is defined by the OpenPGP Working Group of the Internet Engineering Task Force (IETF).

Here is the [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) story.

## Installation

### Framework

ObjectivePGP comes with the prebuild [Static Frameworks](./Frameworks)

1. Download appropriate ObjectivePGP.framework
1. Link framework with the target
    - Add `ObjectivePGP.framework` to "**Link Binary With Libraries**" list for the target.

### Subproject

You can add ObjectivePGP project as a subproject to your application project:

1. Add `ObjectivePGP.xcodeproj` to the project.
1. Add `ObjectivePGP` to "**Target Dependencies**" list for the target.
1. Add `ObjectivePGP` to "**Link Binary With Libraries**" list for the target.
1. Add `libz` and `libbz2` to "**Link Binary With Libraries**" list for the target. These are system libraries.

![screen shot 2017-06-30 at 02 07 42](https://user-images.githubusercontent.com/758033/27715699-3a0dec74-5d39-11e7-8c6c-8b97fb70b33e.png)

### CocoaPods

```ruby
pod 'ObjectivePGP'
```

## Contribution

You are welcome to contribute. Please create [Pull Request](https://github.com/krzyzanowskim/ObjectivePGP/pulls) against `develop` branch.

## The license

The ObjectivePGP stays under a dual license:

- Free for non-commercial use, covered by the standard 2-clause BSD license. That means you have to mention Marcin Krzyżanowski as the original author of this code and reproduce the [LICENSE](./LICENSE.txt) text inside your app.

- Commercial-use license to use in commercial products. Please bear in mind that some free products remain commercial products. Please contact me via [email](http://www.krzyzanowskim.com) for details. 

## Usage

##### Initialization

```objective-c
#include <ObjectivePGP/ObjectivePGP.h>

ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
```

##### Load keys (private or public)

```objective-c
/* Import keys from a keyring file */
[pgp importKeysFromFile:@"/path/to/secring.gpg"];

/* Import keys from a keys file */
[pgp importKeysFromFile:@"/path/to/key.asc"];

/* Import selected key from a keyring */
[pgp importKey:@"979E4B03DFFE30C6" fromFile:@"/path/to/secring.gpg"];
```

##### Search for keys

```objective-c
/* long identifier 979E4B03DFFE30C6 */
PGPKey *key = [pgp findKeyForIdentifier:@"979E4B03DFFE30C6"];

/* Short identifier 979E4B03 (the same result as previous) */
PGPKey *key = [pgp findKeyForIdentifier:@"979E4B03"];

/* First key that match given user identifier string. */
PGPKey *key = [pgp findKeysForUserID:@"Name <email@example.com>"];
```

##### Export keys (private or public)

```objective-c
/* Export all public keys to file */
if ([pgp exportKeysOfType:PGPPartialKeyPublic toFile:@"pubring.gpg" error:nil]) {
    // success
}

/* Export single key */
/* export key and save as armored (ASCII) file */
PGPKey *key = [self.oPGP findKeyForIdentifier:@"979E4B03DFFE30C6"];
NSData *armoredKeyData = [pgp exportKey:key armored:YES];
[armoredKeyData writeToFile:@"pubkey.asc" atomically:YES];
```

##### Sign data (or file)

```objective-c
NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];

/* Choose a key to use to sign the data */
PGPKey *key = [self.oPGP findKeyForIdentifier:@"979E4B03DFFE30C6"];

/* Sign and return only a signature data (detached = YES) */
NSData *signature = [pgp signData:fileContent usingKey:key passphrase:nil detached:YES error:nil];

/* Sign and return a data with the signature (detached = NO) */
NSData *signedData = [pgp signData:fileContent usingSecretKey:key passphrase:nil detached:NO error:nil];
```

##### Verify signature from data (or file)

```objective-c
/* embedded signature */
NSData *signedContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.signed"];
if ([pgp verifyData:signedContent]) {
    // Success
}

/* detached signature */
NSData *signatureContent = [NSData dataWithContentsOfFile:@"/path/file/to/signature"];
NSData *dataContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];
if ([pgp verifyData:dataContent withSignature:signatureContent]) {
    // Success
}
```

##### Encrypt data with previously loaded public key

```
NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/plaintext.txt"];

/* Choose the public key to use to encrypt data. Must be imported previously */
PGPKey *key = [self.oPGP findKeyForIdentifier:@"979E4B03DFFE30C6"];

/* Encrypt data. Armor output (ASCII file)  */
NSData *encryptedData = [pgp encryptData:fileContent usingKeys:@[key] armored:YES error:nil];
if (encryptedData) {
    // Success
}
```

##### Decrypt data with previously loaded private key
    
```objective-c
NSData *encryptedFileContent = [NSData dataWithContentsOfFile:@"/path/data.enc"];

/* If key is encrypted with the password, you can provide a password key here. */
NSData *decryptedData = [pgp decryptData:encryptedFileContent passphrase:nil error:nil];
if (decryptedData) {
    // Success
}
```

## Changelog

See [CHANGELOG](./CHANGELOG)

Known limitations:

- Embedded signatures are not supported.
- ZIP compression not fully supported.
- Blowfish, Twofish and Elgamal are not supported.
- Missing external configuration for default values.

### Acknowledgment

This product uses software developed by the [OpenSSL](http://www.openssl.org/) Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

### Author

[Marcin Krzyżanowski](http://krzyzanowskim.com)