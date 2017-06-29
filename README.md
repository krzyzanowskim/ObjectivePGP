ObjectivePGP
============

ObjectivePGP is [OpenPGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP) implementation for iOS, tvOS and macOS.

See [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) for full story.

## Installation

### CocoaPods

	pod 'ObjectivePGP'
	
## Contribution

You are welcome to contribute. Current version can be found on branch `master`. 
If you want fix the bug, please create Pull Request against `develop` branch.

## The licence

Free for non-commercial use, covered by a standard 2-clause BSD license. That means you have to mention Marcin Krzyżanowski as the original author of this code and reproduce the LICENSE text inside your app.

You can purchase commercial and non-attribution-license for not having to include the LICENSE text. 

Please contact me via email for inquiries.

## Usage

##### Initialization

	#include <ObjectivePGP/ObjectivePGP.h>
	
	ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
	
##### Load keys (private or public)

	/* From file */
	[pgp importKeysFromFile:@"/path/to/secring.gpg"];
	[pgp importKeysFromFile:@"/path/to/key.asc"];
	
	/* Load single key from keyring */
	[pgp importKey:@"979E4B03DFFE30C6" fromFile:@"/path/to/secring.gpg"];
	
##### Search for keys

	/* long identifier 979E4B03DFFE30C6 */
	PGPKey *key = [pgp getKeyForIdentifier:@"979E4B03DFFE30C6"];

	/* short identifier 979E4B03 (the same result as previous) */
	PGPKey *key = [pgp getKeyForIdentifier:@"979E4B03"];
	
	/* first key that match given user */
	PGPKey *key = [pgp getKeysForUserID:@"Name <email@example.com>"];
	
##### Export keys (private or public)

	/* export all public keys to file */
      NSError *error;
	BOOL result = [pgp exportKeysOfType:PGPPartialKeyPublic toFile:@"pubring.gpg" error:&error];
	if (result) {
		// success
	}
	
	PGPKey *myPublicKey = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6"];
      if (myPublicKey.publicKey) {
    	  /* export public key and save as armored (ASCII) file */
    	  NSData *armoredKeyData = [pgp exportKey:myPublicKey armored:YES];
    	  [armoredKeyData writeToFile:@"pubkey.asc" atomically:YES];
      }

##### Sign data (or file)

	NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];

	/* find key to sign */
	PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6"];

	/* sign and return only a signature (detached = YES) */
	NSData *signature = [pgp signData:fileContent usingSecretKey:keyToSign passphrase:nil detached:YES];

	/* sign and return signed data (detached = NO) */
	NSData *signedData = [pgp signData:fileContent usingSecretKey:keyToSign passphrase:nil detached:NO];
	
##### Verify signature from data (or file)

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
	
##### Encrypt data with previously loaded public key

	NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];
    
	/* public key to encrypt data, must be loaded previously */
	PGPKey *keyToEncrypt = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6"];

	/* encrypt data, armor output (ASCII file)  */
    NSError *error;
	NSData *encryptedData = [pgp encryptData:fileContent usingPublicKey:keyToEncrypt armored:YES error:&error];
	if (encryptedData && !error) {
		// Success
	}

##### Decrypt data with previously loaded private key
    
	NSData *encryptedFileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.gpg"];
	
	/* need provide passphrase if required */
    NSError *error;
	NSData *decryptedData = [pgp decryptData:encryptedFileContent passphrase:nil error:&error];
	if (decryptedData && !error) {
		// Success
	}

## Changelog

See [CHANGELOG](./CHANGELOG) file.

Known limitations

- Embedded signatures are not supported.
- ZIP compression not fully supported.
- Blowfish, Twofish and Elgamal are not supported.
- No external configuration for default values.

### Acknowledgment

This product uses software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

### Author

Marcin Krzyżanowski

Follow me on Twitter [@krzyzanowskim](http://twitter.com/krzyzanowskim)
