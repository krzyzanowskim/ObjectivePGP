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
#import "PGPSignaturePacket.h"
#import "PGPPacketFactory.h"
#import "PGPUserIDPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPLiteralPacket.h"
#import "PGPUser.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPLiteralPacket.h"
#import "PGPArmor.h"
#import "PGPCryptoUtils.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"
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

// 16 or 8 chars identifier
- (PGPKey *) getKeyForIdentifier:(NSString *)keyIdentifier
{
    if (keyIdentifier.length < 8 && keyIdentifier.length > 16)
        return nil;

    __block PGPKey *foundKey = nil;
    [self.keys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        PGPKey *key = obj;
        PGPPublicKeyPacket *primaryPacket = (PGPPublicKeyPacket *)key.primaryKeyPacket;
        if (keyIdentifier.length == 16 && [[primaryPacket.keyID.longKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
            foundKey = key;
        } else if (keyIdentifier.length == 8 && [[primaryPacket.keyID.shortKeyString uppercaseString] isEqualToString:[keyIdentifier uppercaseString]]) {
            foundKey = key;
        }

        if (foundKey) {
            *stop = YES;
        }
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

- (BOOL) exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError **)error
{
    return [self exportKeys:[self getKeysOfType:type] toFile:path error:error];
}

- (BOOL) exportKeys:(NSArray *)keys toFile:(NSString *)path error:(NSError **)error
{
    BOOL result = YES;
    for (PGPKey *key in keys) {
        result = result && [self appendKey:key toKeyring:path error:error];
    }
    return result;
}


- (BOOL) appendKey:(PGPKey *)key toKeyring:(NSString *)path error:(NSError **)error
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
        result = [fm createFileAtPath:path contents:keyData attributes:@{NSFileProtectionKey: NSFileProtectionComplete,
                                                                NSFilePosixPermissions: @(0600)}];
    } else {
        @try {
            NSFileHandle *fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:path];
            [fileHandle seekToEndOfFile];
            [fileHandle writeData:keyData];
            [fileHandle closeFile];
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

#pragma mark - Encrypt 

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error
{
    // Message.prototype.encrypt = function(keys) {
    NSMutableData *encryptedMessage = [NSMutableData data];
    
    //PGPPublicKeyEncryptedSessionKeyPacket goes here
    PGPSymmetricAlgorithm preferredSymmeticAlgorithm = [publicKey preferredSymmetricAlgorithm];

    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlhorithm:preferredSymmeticAlgorithm];
    NSMutableData *sessionKeyData = [NSMutableData data];
    for (int i = 0; i < (keySize); i++) {
        Byte b = arc4random_uniform(126) + 1;
        [sessionKeyData appendBytes:&b length:1];
    }
    
    PGPPublicKeyPacket *encryptionKeyPacket = (PGPPublicKeyPacket *)[publicKey encryptionKeyPacket];
    if (encryptionKeyPacket) {
        // var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
        PGPPublicKeyEncryptedSessionKeyPacket *eskKeyPacket = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] init];
        eskKeyPacket.keyID = encryptionKeyPacket.keyID;
        eskKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.publicKeyAlgorithm;
        //pkESKeyPacket.encrypt(encryptionKeyPacket);
        [eskKeyPacket encrypt:encryptionKeyPacket sessionKeyData:sessionKeyData sessionKeyAlgorithm:preferredSymmeticAlgorithm error:error];
        NSAssert(!(*error), @"Missing literal data");
        if (*error) {
            return nil;
        }
        [encryptedMessage appendData:[eskKeyPacket exportPacket:nil]];
    }
    
    //TODO: there is more.. integrity packet

    // literal packet
    PGPLiteralPacket *literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToEncrypt];
    literalPacket.filename = nil;
    literalPacket.timestamp = [NSDate date];
    NSAssert(!(*error), @"Missing literal data");
    if (*error) {
        return nil;
    }

    //  Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
    PGPSymmetricallyEncryptedDataPacket *symEncryptedDataPacket = [[PGPSymmetricallyEncryptedDataPacket alloc] init];
    [symEncryptedDataPacket encrypt:[literalPacket exportPacket:nil] withPublicKeyPacket:encryptionKeyPacket symmetricAlgorithm:preferredSymmeticAlgorithm sessionKeyData:sessionKeyData];
    [encryptedMessage appendData:[symEncryptedDataPacket exportPacket:error]];
    if (*error) {
        return nil;
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
    NSData *signaturePacketData = nil;

    //TODO: Some defaults
    PGPHashAlgorithm preferedHashAlgorithm = PGPHashSHA1;

    PGPSignaturePacket *signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument
                                                                hashAlgorithm:preferedHashAlgorithm];

    [signaturePacket signData:dataToSign secretKey:secretKey passphrase:passphrase userID:nil];
    NSError *exportError = nil;
    signaturePacketData = [signaturePacket exportPacket:&exportError];
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
    NSArray *loadedKeys = [self loadKeysFromFile:path];
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

- (NSArray *) loadKeysFromFile:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:NO]) {
        return nil;
    }

    NSData *fileData = [NSData dataWithContentsOfFile:fullPath];
    if (!fileData) {
        return nil;
    }

    NSData *binRingData = fileData;
    // detect if armored, check for strin -----BEGIN PGP
    if ([PGPArmor isArmoredData:fileData]) {
        NSError *deadmorError = nil;
        NSString *armoredString = [[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding];
        binRingData = [PGPArmor readArmoredData:armoredString error:&deadmorError];
        if (deadmorError) {
            return nil;
        }
    }

    NSArray *parsedKeys = [self readPacketsBinaryData:binRingData];
    if (parsedKeys.count == 0) {
        return nil;
    }

    return parsedKeys;
}

#pragma mark - Private

/**
 *  Parse keyring data
 *
 *  @param keyringData Keyring data
 *
 *  @return Array of PGPKey
 */
- (NSArray *) readPacketsBinaryData:(NSData *)keyringData
{
    NSMutableArray *keys = [NSMutableArray array];
    NSMutableArray *accumulatedPackets = [NSMutableArray array];
    NSUInteger offset = 0;

    while (offset < keyringData.length) {
        
        PGPPacket *packet = [PGPPacketFactory packetWithData:keyringData offset:offset];
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


@end
