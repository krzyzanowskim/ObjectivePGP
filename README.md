ObjectivePGP
============

ObjectivePGP is OpenPGP implementation for iOS and OSX.

See [blog post](http://blog.krzyzanowskim.com/2014/07/31/short-story-about-openpgp-for-ios-and-os-x-objectivepgp/) for full story.

##Installation

###CocoaPods

	pod 'ObjectivePGP', :git => 'https://github.com/krzyzanowskim/ObjectivePGP.git', :branch => :master

##The licence

It is open source and covered by a standard 2-clause BSD license. That means you have to mention Marcin Krzyżanowski as the original author of this code and reproduce the LICENSE text inside your app.

You can purchase a Non-Attribution-License for 75 Euros for not having to include the LICENSE text. I also accept sponsorship for specific enhancements which you might need. Please contact me via email for inquiries.

##Usage

#####Initialization

	#include <ObjectivePGP.h>
	
	ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
	
#####Load keys (private or public)

	/* From file */
	[pgp importKeysFromFile:@"/path/to/secring.gpg" allowDuplicates:NO];
	[pgp importKeysFromFile:@"/path/to/key.asc" allowDuplicates:NO];
	
	/* Load single key from keyring */
	[pgp importKey:@"979E4B03DFFE30C6" fromFile:@"/path/to/secring.gpg"];
	
#####Search for keys

	/* long identifier 979E4B03DFFE30C6 */
	PGPKey *key = [pgp getKeyForIdentifier:@"979E4B03DFFE30C6" type:PGPKeyPublic];
	
	/* short identifier 979E4B03 (the same result as previous) */
	PGPKey *key = [pgp getKeyForIdentifier:@"979E4B03" type:PGPKeyPublic];
	
	/* first key that match given user */
	PGPKey *key = [pgp getKeysForUserID:@"Name <email@example.com>"];
	
#####Export keys (private or public)

	NSError *exportError = nil;
	
	/* export all public keys to file */
	BOOL result = [pgp exportKeysOfType:PGPKeyPublic toFile:@"pubring.gpg" error:&exportError];
	if (result) {
		NSLog(@"success");
	}
	
	PGPKey *myPublicKey = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6" type:PGPKeyPublic];
	
	/* export public key and save as armored (ASCII) file */
	NSData *armoredKeyData = [pgp exportKey:myPublicKey armored:YES];
	[armoredKeyData writeToFile:@"pubkey.asc" atomically:YES];

#####Sign data (or file)

	NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];

	/* choose key to sign */
	PGPKey *keyToSign = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6" type:PGPKeySecret];

	/* sign and return signature (detached = YES) */
	NSData *signature = [pgp signData:fileContent usingSecretKey:keyToSign passphrase:nil detached:YES];

	/* sign and return signed data (detached = NO) */
	NSData *signedData = [pgp signData:fileContent usingSecretKey:keyToSign passphrase:nil detached:NO];
	
#####Verify signature from data (or file)

	/* embedded signature */
	NSData *signedContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.signed"];
	if ([pgp verifyData:signedContent]) {
		NSLog(@"Verification success");
	}
	
	/* detached signature */
	NSData *signatureContent = [NSData dataWithContentsOfFile:@"/path/file/to/signature"];
	NSData *dataContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];
	if ([pgp verifyData:dataContent withSignature:signatureContent]) {
		NSLog(@"Verification success");
	}
	
#####Encrypt data with previously loaded public key

    NSError *error = nil;

	NSData *fileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.txt"];
    
	/* public key to encrypt data, must be loaded previously */
	PGPKey *keyToEncrypt = [self.oPGP getKeyForIdentifier:@"979E4B03DFFE30C6" type:PGPKeyPublic];

	/* encrypt data, armor output (ASCII file)  */
	NSData *encryptedData = [pgp encryptData:fileContent usingPublicKey:keyToEncrypt armored:YES error:&error];
	if (encryptedData && !error) {
		NSLog(@"encryption success");
		[encryptedData writeToFile:@"/path/to/encrypted/file.gpg" atomically:YES]
	}


#####Decrypt data with previously loaded private key
    
	NSData *encryptedFileContent = [NSData dataWithContentsOfFile:@"/path/file/to/data.gpg"];
	
	/* need provide passphrase if required */
    NSError *error = nil;
	NSData *decryptedData = [pgp decryptData:encryptedFileContent passphrase:nil error:&error];
	if (decryptedData && !error) {
		NSLog(@"decryption success");
	}

##Release notes

Version 0.3.2
- CHANGE error handling for sign/verify methods
- FIX disable check for signing key while it can be public to verify.

Version 0.3.1

- NEW multiple keys for single encryption
- NEW error codes PGPErrorPassphraseRequired, PGPErrorPassphraseInvalid
- CHANGE export armored data with \n instead \r\n
- FIX decrypt message using key encrypted with password
- FIX handling armored data regarding newline

Version 0.3

- NEW encrypt for multiple recipients at once
- NEW decrypt with multiple recipients
- NEW read key from file without importing to keyring
- NEW import keys with or without duplicates
- NEW Support for V3 of signature packets
- NEW armv7s binary added
- IMPROVED overall error handling
- IMPROVED preferred key algorithm chooser
- FIX handle DSA keys for encryption
- FIX self certificate validation check
- FIX export multiple keys to single file
- FIX reading user id packet
- FIX other minor fixes

Known limitations

- Embedded signatures are not supported
- ZIP compression not fully supported
- Blowfish and Twofish are not supported
- No external configuration for defaults

###Acknowledgment

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

###Author

Marcin Krzyżanowski

Follow me on Twitter [@krzyzanowskim](http://twitter.com/krzyzanowskim)
