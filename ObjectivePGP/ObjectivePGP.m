//
//  ObjectivePGP.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPPacketFactory.h"
#import "PGPKey.h"
#import "PGPSubKey.h"
#import "PGPSignaturePacket.h"
#import "PGPPacketFactory.h"
#import "PGPUserIDPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPLiteralPacket.h"
#import "PGPUser.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPLiteralPacket.h"
#import "PGPCompressedPacket.h"
#import "PGPArmor.h"
#import "PGPCryptoUtils.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPMPI.h"

@implementation ObjectivePGP

- (NSArray *)keys
{
    if (!_keys) {
        _keys = [NSArray array];
    }
    return _keys;
}

#pragma mark - Search

// full user identifier
- (NSArray *) getKeysForUserID:(NSString *)userID
{
    NSMutableArray *foundKeysArray = [NSMutableArray array];
    [self.keys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPKey *key = obj;
        for (PGPUser *user in key.users) {
            if ([user.userID isEqualToString:userID]) {
                [foundKeysArray addObject:key];
            }
        }
    }];
    return foundKeysArray.count > 0 ? [foundKeysArray copy] : nil;
}

- (PGPKey *) getKeyForKeyID:(PGPKeyID *)searchKeyID type:(PGPKeyType)keyType
{
    if (!searchKeyID) {
        return nil;
    }
    
    __block PGPKey *foundKey = nil;
    [[self getKeysOfType:keyType] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPKey *key = obj;
        if ([key.keyID isEqualToKeyID:searchKeyID]) {
            foundKey = key;
            *stop = YES;
        }
        
        [key.subKeys enumerateObjectsUsingBlock:^(id objsub, NSUInteger idxsub, BOOL *stopsub) {
            PGPSubKey *subKey = objsub;
            if ([subKey.keyID isEqualToKeyID:searchKeyID]) {
                foundKey = key;
                *stopsub = YES;
                *stop = YES;
            }
            
        }];
    }];
    return foundKey;
}

// 16 or 8 chars identifier
//TODO: renamte to getKeyForFingerprint or something
- (PGPKey *) getKeyForIdentifier:(NSString *)keyIdentifier type:(PGPKeyType)keyType
{
    if (keyIdentifier.length < 8 && keyIdentifier.length > 16)
        return nil;

    __block PGPKey *foundKey = nil;
    [[self getKeysOfType:keyType] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPKey *key = obj;
        PGPPublicKeyPacket *primaryPacket = (PGPPublicKeyPacket *)key.primaryKeyPacket;
        if (keyIdentifier.length == 16 && [[primaryPacket.keyID.longKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
            foundKey = key;
            *stop = YES;
            return;
        } else if (keyIdentifier.length == 8 && [[primaryPacket.keyID.shortKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
            foundKey = key;
            *stop = YES;
            return;
        }

        [[key subKeys] enumerateObjectsUsingBlock:^(id subobj, NSUInteger subidx, BOOL *substop) {
            PGPSubKey *subKey = subobj;
            PGPPublicKeyPacket *subprimaryPacket = (PGPPublicKeyPacket *)subKey.primaryKeyPacket;
            if (keyIdentifier.length == 16 && [[subprimaryPacket.keyID.longKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
                foundKey = key;
                *substop = YES;
                *stop = YES;
            } else if (keyIdentifier.length == 8 && [[subprimaryPacket.keyID.shortKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
                foundKey = key;
                *substop = YES;
                *stop = YES;
            }
        }];
    }];
    return foundKey;
}

- (NSArray *) getKeysOfType:(PGPKeyType)keyType
{
    NSMutableArray *keysArray = [NSMutableArray array];
    for (PGPKey *key in self.keys) {
        if (key.type == keyType)
            [keysArray addObject:key];
    }
    return [keysArray copy];
}

#pragma mark - Save

- (BOOL) exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing *)error
{
    return [self exportKeys:[self getKeysOfType:type] toFile:path error:error];
}

- (BOOL) exportKeys:(NSArray *)keys toFile:(NSString *)path error:(NSError * __autoreleasing *)error
{
    BOOL result = YES;
    for (PGPKey *key in keys) {
        result = result && [self appendKey:key toKeyring:path error:error];
    }
    return result;
}


- (BOOL) appendKey:(PGPKey *)key toKeyring:(NSString *)path error:(NSError * __autoreleasing *)error
{
    NSFileManager *fm = [NSFileManager defaultManager];

    if (!path) {
        return NO;
    }

    NSData *keyData = [key export:error];
    if (*error) {
        return NO;
    }

    BOOL result = NO;
    if (![fm fileExistsAtPath:path]) {
        NSDictionary *attributes = nil;
#ifdef __IPHONE_OS_VERSION_MAX_ALLOWED
        attributes = @{NSFileProtectionKey: NSFileProtectionComplete, NSFilePosixPermissions: @(0600)};
#else
        attributes = @{NSFilePosixPermissions: @(0600)};
#endif
        result = [fm createFileAtPath:path contents:keyData attributes:attributes];
    } else {
        @try {
            NSFileHandle *fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:path];
            [fileHandle seekToEndOfFile];
            [fileHandle writeData:keyData];
            [fileHandle closeFile];
            result = YES;
        }
        @catch (NSException *exception) {
            result = NO;
        }
    }
    return result;
}

- (NSData *) exportKey:(PGPKey *)key armored:(BOOL)armored
{
    NSAssert(key, @"Missing parameter");
    if (!key) {
        return nil;
    }

    NSError *exportError = nil;
    NSData *keyData = [key export:&exportError];
    if (!keyData || exportError) {
        NSLog(@"%@",exportError);
        return nil;
    }

    if (armored) {
        return [PGPArmor armoredData:keyData as:PGPArmorTypePublicKey];
    } else {
        return keyData;
    }
    return nil;
}

#pragma mark - Encrypt & Decrypt

- (NSData *) decryptData:(NSData *)messageDataToDecrypt passphrase:(NSString *)passphrase error:(NSError * __autoreleasing *)error
{
    NSData *binaryMessageToDecrypt = [self convertArmoredMessage2BinaryWhenNecessary:messageDataToDecrypt];
    NSAssert(binaryMessageToDecrypt != nil, @"Ivalid input data");
    if (!binaryMessageToDecrypt) {
        return nil;
    }
    
    // parse packets
    NSArray *packets = [self readPacketsFromData:binaryMessageToDecrypt];
    
    PGPSymmetricAlgorithm sessionKeyAlgorithm = 0;
    NSData *sessionKeyData = nil;
    NSData *decryptedData = nil;
    PGPSecretKeyPacket *decryptionSecretKeyPacket = nil; // found secret key to used to decrypt
    
    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPPublicKeyEncryptedSessionKeyPacketTag:
            {
                // 1
                PGPPublicKeyEncryptedSessionKeyPacket *pkESKPacket = (PGPPublicKeyEncryptedSessionKeyPacket *)packet;
                PGPKey *decryptionSecretKey = [self getKeyForKeyID:pkESKPacket.keyID type:PGPKeySecret];
                PGPSecretKeyPacket *decryptKeyPacket = (PGPSecretKeyPacket *)[decryptionSecretKey decryptionKeyPacket];
                NSAssert([decryptKeyPacket isKindOfClass:[PGPSecretKeyPacket class]], @"Invalid secret key");

                // decrypt key if necessary
                decryptionSecretKeyPacket = decryptKeyPacket;
                if (decryptionSecretKeyPacket.isEncrypted) {
                    decryptionSecretKeyPacket = [decryptionSecretKeyPacket decryptedKeyPacket:passphrase error:error];
                    if (error && *error) {
                        return nil;
                    }
                }
                
                sessionKeyData = [pkESKPacket decryptSessionKeyData:decryptionSecretKeyPacket sessionKeyAlgorithm:&sessionKeyAlgorithm error:error];
                NSAssert(sessionKeyData, @"PublicKeyEncryptedSessionKeyPacket decryption failed");
                NSAssert(sessionKeyAlgorithm > 0, @"Invalid session key algorithm");
                
                if (!sessionKeyData) {
                    return nil;
                }
            }
                break;
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag:
            {
                // 2
                NSAssert(sessionKeyData, @"Missing session key data");
                NSAssert(decryptionSecretKeyPacket, @"Decryption secret key packet not found");
                if (!decryptionSecretKeyPacket) {
                    if (error) {
                        *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unable to find secret key"}];
                    }
                    return nil;
                }
                
                // decrypt PGPSymmetricallyEncryptedIntegrityProtectedDataPacket
                PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *symEncryptedDataPacket = (PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *)packet;
                decryptedData = [symEncryptedDataPacket decryptWithSecretKeyPacket:decryptionSecretKeyPacket sessionKeyAlgorithm:sessionKeyAlgorithm sessionKeyData:sessionKeyData error:error];
                if (!decryptedData) {
                    return nil;
                }
            }
                break;
            default:
                
                break;
        }
    }
    return decryptedData;
}

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKey:(PGPKey *)publicKey armored:(BOOL)armored error:(NSError * __autoreleasing *)error
{
    return [self encryptData:dataToEncrypt usingPublicKeys:@[publicKey] armored:armored error:error];
}

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing *)error
{
    // Message.prototype.encrypt = function(keys) {
    NSMutableData *encryptedMessage = [NSMutableData data];
    
    // Prepare literal packet
    PGPLiteralPacket *literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToEncrypt];
    literalPacket.filename = nil;
    literalPacket.timestamp = [NSDate date];
    NSAssert(!(*error), @"Missing literal data");
    if (*error) {
        return nil;
    }
    NSData *literalPacketData = [literalPacket exportPacket:error];
    if (*error) {
        return nil;
    }
    
    PGPCompressedPacket *compressedPacket = [[PGPCompressedPacket alloc] initWithData:literalPacketData type:PGPCompressionBZIP2];
    NSData *compressedPacketData = [compressedPacket exportPacket:error];
    if (*error) {
        return nil;
    }

    //PGPPublicKeyEncryptedSessionKeyPacket goes here
    //FIXME: check all keys preferency and choose common prefered
    PGPSymmetricAlgorithm preferredSymmeticAlgorithm = [PGPKey preferredSymmetricAlgorithmForKeys:publicKeys];
    
    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:preferredSymmeticAlgorithm];
    NSMutableData *sessionKeyData = [NSMutableData data];
    for (int i = 0; i < (keySize); i++) {
        UInt8 byte = arc4random_uniform(255);
        [sessionKeyData appendBytes:&byte length:1];
    }

    for (PGPKey *publicKey in publicKeys) {
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        // Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
        // ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
        
        // ESK
        PGPPublicKeyPacket *encryptionKeyPacket = (PGPPublicKeyPacket *)[publicKey encryptionKeyPacket];
        if (encryptionKeyPacket) {
            // var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
            PGPPublicKeyEncryptedSessionKeyPacket *eskKeyPacket = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] init];
            eskKeyPacket.keyID = encryptionKeyPacket.keyID;
            eskKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.publicKeyAlgorithm;
            [eskKeyPacket encrypt:encryptionKeyPacket sessionKeyData:sessionKeyData sessionKeyAlgorithm:preferredSymmeticAlgorithm error:error];
            NSAssert(!(*error), @"Missing literal data");
            if (*error) {
                return nil;
            }
            [encryptedMessage appendData:[eskKeyPacket exportPacket:error]];
            if (*error) {
                return nil;
            }
        }
    }

    PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *symEncryptedDataPacket = [[PGPSymmetricallyEncryptedIntegrityProtectedDataPacket alloc] init];
    [symEncryptedDataPacket encrypt:compressedPacketData
                 symmetricAlgorithm:preferredSymmeticAlgorithm
                     sessionKeyData:sessionKeyData];
    
    [encryptedMessage appendData:[symEncryptedDataPacket exportPacket:error]];
    if (*error) {
        return nil;
    }

    if (armored) {
        return [PGPArmor armoredData:encryptedMessage as:PGPArmorTypeMessage];
    }

    return [encryptedMessage copy];
}

#pragma mark - Sign & Verify

- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase
{
    return [self signData:dataToSign withKeyForUserID:userID passphrase:passphrase detached:YES];
}

- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase detached:(BOOL)detached
{
    PGPKey *key = [[self getKeysForUserID:userID] lastObject];
    NSAssert(key, @"Key is missing");

    if (!key) {
        return nil;
    }

    return [self signData:dataToSign usingSecretKey:key passphrase:passphrase];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase
{
    return [self signData:dataToSign usingSecretKey:secretKey passphrase:passphrase detached:YES];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase detached:(BOOL)detached
{
    //TODO: configurable defaults for prefered hash
    return [self signData:dataToSign usingSecretKey:secretKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:detached];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase hashAlgorithm:(PGPHashAlgorithm)preferedHashAlgorithm detached:(BOOL)detached
{
    PGPSignaturePacket *signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument
                                                                hashAlgorithm:preferedHashAlgorithm];

    [signaturePacket signData:dataToSign secretKey:secretKey passphrase:passphrase userID:nil];
    NSError *exportError = nil;
    NSData *signaturePacketData = [signaturePacket exportPacket:&exportError];
    NSAssert(!exportError,@"Error on export packet");

    // Signed Message :- Signature Packet, Literal Message
    NSMutableData *signedMessage = [NSMutableData data];
    if (!detached) {
        // OnePass
        PGPOnePassSignaturePacket *onePassPacket = [[PGPOnePassSignaturePacket alloc] init];
        onePassPacket.signatureType = signaturePacket.type;
        onePassPacket.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
        onePassPacket.hashAlgorith = signaturePacket.hashAlgoritm;

        onePassPacket.keyID = [signaturePacket issuerKeyID];

        onePassPacket.notNested = YES;
        NSError *onePassExportError = nil;
        [signedMessage appendData:[onePassPacket exportPacket:&onePassExportError]];
        NSAssert(!onePassExportError, @"Missing one password data");

        // Literal
        PGPLiteralPacket *literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToSign];
        literalPacket.filename = nil;
        literalPacket.timestamp = [NSDate date];
        NSError *literalExportError = nil;
        [signedMessage appendData:[literalPacket exportPacket:&literalExportError]];
        NSAssert(!literalExportError, @"Missing literal data");
    }
    [signedMessage appendData:signaturePacketData];
    return [signedMessage copy];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData
{
    if (!signedData || !signatureData) {
        return NO;
    }

    // search for key in keys
    id packet = [PGPPacketFactory packetWithData:signatureData offset:0];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        return NO;
    }

    PGPSignaturePacket *signaturePacket = packet;
    PGPKeyID *issuerKeyID = [signaturePacket issuerKeyID];

    PGPKey *issuerKey = [self findKeyForKeyID:issuerKeyID];
    if (!issuerKey) {
        return NO;
    }

    return [self verifyData:signedData withSignature:signatureData usingKey:issuerKey];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey
{
    if (!publicKey || !signatureData || !signatureData) {
        return NO;
    }

    id packet = [PGPPacketFactory packetWithData:signatureData offset:0];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        return NO;
    }

    PGPSignaturePacket *signaturePacket = packet;
    BOOL verified = [signaturePacket verifyData:signedData withKey:publicKey userID:nil];

    return verified;
}

- (BOOL) verifyData:(NSData *)signedDataPackets
{
    // this is propably not the best solution when it comes to memory consumption
    // because literal data is copied more than once (first at parse phase, then when is come to build signature packet data
    // I belive this is unecessary but require more work. Schedule to v2.0
    @autoreleasepool {
        // search for signature packet
        NSMutableArray *accumulatedPackets = [NSMutableArray array];
        NSUInteger offset = 0;

        //TODO: dont parse data here, get raw data and pass to verifyData:withsignature:
        while (offset < signedDataPackets.length) {

            PGPPacket *packet = [PGPPacketFactory packetWithData:signedDataPackets offset:offset];
            if (packet) {
                [accumulatedPackets addObject:packet];
            }

            offset = offset + packet.headerData.length + packet.bodyData.length;
        }

        //NSLog(@"%@",accumulatedPackets);

        PGPSignaturePacket *signaturePacket = nil;
        PGPLiteralPacket *literalDataPacket = nil;

        for (PGPPacket *packet in accumulatedPackets) {
            if (packet.tag == PGPSignaturePacketTag) {
                signaturePacket = (PGPSignaturePacket *)packet;
            }
            if (packet.tag == PGPLiteralDataPacketTag) {
                literalDataPacket = (PGPLiteralPacket *)packet;
            }
        }

        NSAssert(signaturePacket && literalDataPacket, @"Missing signature packet or literal data packet");
        if (!signaturePacket || !literalDataPacket) {
            return NO;
        }

        // do not build signature, use data that was readed from signedDataPackets
        // to build final data and avoid unecesarry copying data dataWithBytesNoCopy:length:freeWhenDone: is used
        // signaturePacket and literalDataPacket is strong in this scope so will not be released
        // before verification process end.
        NSMutableData *signaturePacketData = [NSMutableData data];
        [signaturePacketData appendData:[NSData dataWithBytesNoCopy:(void *)signaturePacket.headerData.bytes length:signaturePacket.headerData.length freeWhenDone:NO]];
        [signaturePacketData appendData:[NSData dataWithBytesNoCopy:(void *)signaturePacket.bodyData.bytes length:signaturePacket.bodyData.length freeWhenDone:NO]];

        return [self verifyData:literalDataPacket.literalRawData withSignature:signaturePacketData];
    }
}

#pragma mark - Parse keyring

/**
 *  Load keyring file (secring or pubring)
 *
 *  @param path Path to file
 *
 *  @return YES on success
 */
- (NSArray *) importKeysFromFile:(NSString *)path
{
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    
    NSArray *loadedKeys = [self loadKeysFromFile:path];
    self.keys = [self.keys arrayByAddingObjectsFromArray:loadedKeys];
    return loadedKeys;
}

- (NSArray *) importKeysFromData:(NSData *)data
{
    if (!data) {
        return nil;
    }
    
    NSArray *loadedKeys = [self loadKeysFromData:data];
    self.keys = [self.keys arrayByAddingObjectsFromArray:loadedKeys];
    return loadedKeys;
}

- (BOOL) importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    NSArray *loadedKeys = [self loadKeysFromFile:fullPath];
    if (loadedKeys.count == 0) {
        return NO;
    }

    __block BOOL foundKey = NO;
    [loadedKeys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPKey *key = obj;

        if ([key.primaryKeyPacket isKindOfClass:[PGPPublicKeyPacket class]]) {
            PGPPublicKeyPacket *keyPacket = (PGPPublicKeyPacket *)key.primaryKeyPacket;
            if ([[keyPacket.keyID.shortKeyString uppercaseString] isEqualToString:[shortKeyStringIdentifier uppercaseString]])
            {
                self.keys = [self.keys arrayByAddingObject:key];
                foundKey = YES;
                *stop = YES;
            }
        }
    }];
    
    return foundKey;
}

#pragma mark - Private

// private
- (NSArray *) loadKeysFromFile:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];
    
    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:&isDirectory]) {
        return nil;
    }
    
    if (isDirectory) {
        return nil;
    }
    
    NSError *error = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe | NSDataReadingUncached error:&error];
    if (!fileData || error) {
        return nil;
    }
    
    return [self loadKeysFromData:fileData];
}

// private
- (NSArray *) loadKeysFromData:(NSData *)fileData
{
    NSAssert(fileData, @"Missing data");
    if (!fileData) {
        return nil;
    }

    NSData *binRingData = [self convertArmoredMessage2BinaryWhenNecessary:fileData];
    NSAssert(binRingData != nil, @"Invalid input data");
    if (!binRingData) {
        return nil;
    }
    
    NSArray *parsedKeys = [self readKeysFromData:binRingData];
    if (parsedKeys.count == 0) {
        return nil;
    }
    
    return parsedKeys;
}



- (NSArray *) readPacketsFromData:(NSData *)keyringData
{
    NSMutableArray *accumulatedPackets = [NSMutableArray array];
    NSUInteger offset = 0;
    
    while (offset < keyringData.length) {
        
        PGPPacket *packet = [PGPPacketFactory packetWithData:keyringData offset:offset];
        if (packet) {
            [accumulatedPackets addObject:packet];
        }
        
        offset = offset + packet.headerData.length + packet.bodyData.length;
    }
    
    return [accumulatedPackets copy];
}

/**
 *  Parse PGP packets data
 *
 *  @param messageData PGP Message data with packets
 *
 *  @return Array of PGPKey
 */
- (NSArray *) readKeysFromData:(NSData *)messageData
{
    NSMutableArray *keys = [NSMutableArray array];
    NSMutableArray *accumulatedPackets = [NSMutableArray array];
    NSUInteger offset = 0;

    while (offset < messageData.length) {
        
        PGPPacket *packet = [PGPPacketFactory packetWithData:messageData offset:offset];
        if (packet) {
            if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
                PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
                [keys addObject:key];
                [accumulatedPackets removeAllObjects];
            }
            [accumulatedPackets addObject:packet];
        }

        offset = offset + packet.headerData.length + packet.bodyData.length;
    }

    if (accumulatedPackets.count > 1) {
        PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
        [keys addObject:key];
        [accumulatedPackets removeAllObjects];
    }
    
    return [keys copy];
}

- (PGPKey *) findKeyForKeyID:(PGPKeyID *)keyID
{
    PGPKey *foundKey = nil;
    for (PGPKey *key in self.keys) {
        for (PGPPublicKeyPacket *keyPacket in key.allKeyPackets) {
            if (![keyPacket isKindOfClass:[PGPPublicKeyPacket class]]) {
                continue;
            }

            if ([keyPacket.keyID isEqualToKeyID:keyID]) {
                foundKey = key;
                goto found_key_label;
            }
        }
    }

found_key_label:
    return foundKey;
}

- (NSData *) convertArmoredMessage2BinaryWhenNecessary:(NSData *)binOrArmorData
{
    NSData *binRingData = binOrArmorData;
    // detect if armored, check for strin -----BEGIN PGP
    if ([PGPArmor isArmoredData:binRingData]) {
        NSError *deadmorError = nil;
        NSString *armoredString = [[NSString alloc] initWithData:binRingData encoding:NSUTF8StringEncoding];
        
        // replace \n to \r\n
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"];
        
        binRingData = [PGPArmor readArmoredData:armoredString error:&deadmorError];
        if (deadmorError) {
            return nil;
        }
    }
    return binRingData;
}


@end
