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
#import "PGPModificationDetectionCodePacket.h"
#import "PGPLiteralPacket.h"
#import "PGPCompressedPacket.h"
#import "PGPArmor.h"
#import "PGPCryptoUtils.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPMPI.h"

@implementation ObjectivePGP

- (NSArray<PGPKey *> *)keys
{
    if (!_keys) {
        _keys = [NSArray<PGPKey *> array];
    }
    return _keys;
}

#pragma mark - Search

// full user identifier
- (nullable NSArray<PGPKey *> *) getKeysForUserID:(nonnull NSString *)userID
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

- (nullable PGPKey *) getKeyForKeyID:(nonnull PGPKeyID *)searchKeyID type:(PGPKeyType)keyType
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
//TODO: rename to getKeyForFingerprint or something
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

- (nonnull NSArray<PGPKey *> *) getKeysOfType:(PGPKeyType)keyType
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
    return [self decryptData:messageDataToDecrypt passphrase:passphrase verifyWithPublicKey:nil signed:nil valid:nil integrityProtected:nil error:error];
}

- (NSData *) decryptData:(NSData *)messageDataToDecrypt passphrase:(NSString *)passphrase verifyWithPublicKey:(PGPKey *)publicKey signed:(BOOL*)isSigned valid:(BOOL*)isValid integrityProtected:(BOOL*)isIntegrityProtected error:(NSError * __autoreleasing *)error
{
    NSData *binaryMessageToDecrypt = [self convertArmoredMessage2BinaryWhenNecessary:messageDataToDecrypt];
    NSAssert(binaryMessageToDecrypt != nil, @"Invalid input data");
    if (!binaryMessageToDecrypt) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid input data"}];
        }
        return nil;
    }
    
    // parse packets
    NSArray *packets = [self readPacketsFromData:binaryMessageToDecrypt];
    
    PGPSymmetricAlgorithm sessionKeyAlgorithm = 0;
    PGPSecretKeyPacket *decryptionSecretKeyPacket = nil; // found secret key to used to decrypt
    
    // 1. search for valid and known (do I have specified key?) ESK
    PGPPublicKeyEncryptedSessionKeyPacket *eskPacket = nil;
    for (PGPPacket *packet in packets) {
        if (packet.tag == PGPPublicKeyEncryptedSessionKeyPacketTag) {
            PGPPublicKeyEncryptedSessionKeyPacket *pkESKPacket = (PGPPublicKeyEncryptedSessionKeyPacket *)packet;
            PGPKey *decryptionSecretKey = [self getKeyForKeyID:pkESKPacket.keyID type:PGPKeySecret];
            if (!decryptionSecretKey) {
                continue;
            }
            
            decryptionSecretKeyPacket = (PGPSecretKeyPacket *)[decryptionSecretKey decryptionKeyPacketWithID:pkESKPacket.keyID error:error];

            // decrypt key with passphrase if encrypted
            if (decryptionSecretKeyPacket.isEncryptedWithPassword) {
                
                if (!passphrase) {
                    if (error) {
                        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseRequired userInfo:@{NSLocalizedDescriptionKey: @"Password is required for key"}];
                    }
                    return nil;
                }
                
                decryptionSecretKeyPacket = [decryptionSecretKeyPacket decryptedKeyPacket:passphrase error:error];
                if (error && *error) {
                    return nil;
                }
            }
            eskPacket = pkESKPacket;
        }
    }
    
    if (error && *error) {
        return nil;
    }
    
    NSAssert(eskPacket, @"Valid PublicKeyEncryptedSessionKeyPacket not found");
    if (!eskPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Valid PublicKeyEncryptedSessionKeyPacket not found"}];
        }
        return nil;
    }
    
    NSAssert(decryptionSecretKeyPacket, @"Decryption secret key packet not found");
    if (!decryptionSecretKeyPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unable to find secret key"}];
        }
        return nil;
    }

    
    NSData *sessionKeyData = [eskPacket decryptSessionKeyData:decryptionSecretKeyPacket sessionKeyAlgorithm:&sessionKeyAlgorithm error:error];
    NSAssert(sessionKeyAlgorithm > 0, @"Invalid session key algorithm");
    
    NSAssert(sessionKeyData, @"Missing session key data");
    if (!sessionKeyData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Missing session key data"}];
        }
        return nil;
    }

    // 2
    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag:
            {
                // decrypt PGPSymmetricallyEncryptedIntegrityProtectedDataPacket
                PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *symEncryptedDataPacket = (PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *)packet;
                packets = [symEncryptedDataPacket decryptWithSecretKeyPacket:decryptionSecretKeyPacket sessionKeyAlgorithm:sessionKeyAlgorithm sessionKeyData:sessionKeyData isIntegrityProtected:isIntegrityProtected error:error];
                if (!packets) {
                    return nil;
                }
            }
                break;
            default:
                
                break;
        }
    }
    
    PGPLiteralPacket *literalPacket;
    PGPSignaturePacket *signaturePacket;
    NSData *plaintextData = nil;
    for (PGPPacket *packet in packets)
    {
        switch (packet.tag) {
            case PGPCompressedDataPacketTag:
            case PGPOnePassSignaturePacketTag:
                // ignore here
                break;
            case PGPLiteralDataPacketTag:
                literalPacket = (PGPLiteralPacket *)packet;
                plaintextData = literalPacket.literalRawData;
                break;
            case PGPSignaturePacketTag:
                signaturePacket = (PGPSignaturePacket *)packet;
                break;
            default:
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unknown packet (expected literal or compressed)"}];
                }
                return nil;
                break;
        }
    }
    
    BOOL _signed = signaturePacket != nil;
    BOOL _valid = NO;
    if (signaturePacket && publicKey)
    {
        _valid = [self verifyData:plaintextData withSignature:signaturePacket.packetData usingKey:publicKey error:nil];
    }
    if (isSigned)
    {
        *isSigned = _signed;
    }
    if (isValid)
    {
        *isValid = _valid;
    }
    return plaintextData;
}

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKey:(PGPKey *)publicKey armored:(BOOL)armored error:(NSError * __autoreleasing *)error
{
    return [self encryptData:dataToEncrypt usingPublicKeys:@[publicKey] armored:armored error:error];
}

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys armored:(BOOL)armored error:(NSError * __autoreleasing *)error
{
    return [self encryptData:dataToEncrypt usingPublicKeys:publicKeys signWithSecretKey:nil passphrase:nil armored:armored error:error];
}

- (NSData *) encryptData:(NSData *)dataToEncrypt usingPublicKeys:(NSArray *)publicKeys signWithSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing *)error
{
    // Message.prototype.encrypt = function(keys) {
    NSMutableData *encryptedMessage = [NSMutableData data];
    
    //PGPPublicKeyEncryptedSessionKeyPacket goes here
    PGPSymmetricAlgorithm preferredSymmeticAlgorithm = [PGPKey preferredSymmetricAlgorithmForKeys:publicKeys];
    
    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:preferredSymmeticAlgorithm];
    uint8_t buf[keySize];
    if (SecRandomCopyBytes(kSecRandomDefault, keySize, buf) == -1) {
        return nil;
    }
    NSMutableData *sessionKeyData = [NSMutableData dataWithBytes:buf length:keySize];
    
    for (PGPKey *publicKey in publicKeys) {
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        // Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
        // ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
        
        // ESK
        PGPPublicKeyPacket *encryptionKeyPacket = (PGPPublicKeyPacket *)[publicKey encryptionKeyPacket:error];
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

    NSData *content;
    // sign data if requested
    if (secretKey)
    {
        content = [self signData:dataToEncrypt usingSecretKey:secretKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:NO error:error];
        if (*error) {
            return nil;
        }
        
    }
    else
    {
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
        content = [compressedPacket exportPacket:error];
        if (*error) {
            return nil;
        }
    }

    PGPSymmetricallyEncryptedIntegrityProtectedDataPacket *symEncryptedDataPacket = [[PGPSymmetricallyEncryptedIntegrityProtectedDataPacket alloc] init];
    [symEncryptedDataPacket encrypt:content
                 symmetricAlgorithm:preferredSymmeticAlgorithm
                     sessionKeyData:sessionKeyData
                              error: error];

    if (*error) {
        return nil;
    }

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

- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase error:(NSError * __autoreleasing *)error
{
    return [self signData:dataToSign withKeyForUserID:userID passphrase:passphrase detached:YES error:error];
}

- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID passphrase:(NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing *)error
{
    PGPKey *key = [[self getKeysForUserID:userID] lastObject];
    NSAssert(key, @"Key is missing");

    if (!key) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Key is missing"}];
        }
        return nil;
    }

    return [self signData:dataToSign usingSecretKey:key passphrase:passphrase error:error];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase error:(NSError * __autoreleasing *)error
{
    return [self signData:dataToSign usingSecretKey:secretKey passphrase:passphrase detached:YES error:error];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase detached:(BOOL)detached  error:(NSError * __autoreleasing *)error
{
    //TODO: configurable defaults for prefered hash
    return [self signData:dataToSign usingSecretKey:secretKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:detached error:error];
}

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey passphrase:(NSString *)passphrase hashAlgorithm:(PGPHashAlgorithm)preferedHashAlgorithm detached:(BOOL)detached error:(NSError * __autoreleasing *)error
{
    PGPSignaturePacket *signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument
                                                                hashAlgorithm:preferedHashAlgorithm];

    [signaturePacket signData:dataToSign secretKey:secretKey passphrase:passphrase userID:nil error:error];
    NSError *exportError = nil;
    NSData *signaturePacketData = [signaturePacket exportPacket:&exportError];
    NSAssert(!exportError,@"Error on export packet");
    if (exportError) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Error on export packet"}];
        }
        return nil;
    }

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
        if (onePassExportError) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing one password data"}];
            }
            return nil;
        }
        
        // Literal
        PGPLiteralPacket *literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToSign];
        literalPacket.filename = nil;
        literalPacket.timestamp = [NSDate date];
        
        NSError *literalExportError = nil;
        [signedMessage appendData:[literalPacket exportPacket:&literalExportError]];
        NSAssert(!literalExportError, @"Missing literal data");
        if (literalExportError) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing literal data"}];
            }
            return nil;
        }
        
//        // Compressed
//        NSError *literalExportError = nil;
//        PGPCompressedPacket *compressedPacket = [[PGPCompressedPacket alloc] initWithData:[literalPacket exportPacket:&literalExportError] type:PGPCompressionBZIP2];
//        NSAssert(!literalExportError, @"Missing literal data");
//        if (literalExportError) {
//            if (error) {
//                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing literal data"}];
//            }
//            return nil;
//        }
//
//        NSError *compressedExportError = nil;
//        [signedMessage appendData:[compressedPacket exportPacket:&compressedExportError]];
//        NSAssert(!compressedExportError, @"Missing compressed data");
//        if (compressedExportError) {
//            if (error) {
//                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing compressed data"}];
//            }
//            return nil;
//        }
    }
    [signedMessage appendData:signaturePacketData];
    return [signedMessage copy];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing *)error
{
    if (!signedData || !signatureData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing input data"}];
        }
        return NO;
    }

    // search for key in keys
    id packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing signature packet"}];
        }
        return NO;
    }

    PGPSignaturePacket *signaturePacket = packet;
    PGPKeyID *issuerKeyID = [signaturePacket issuerKeyID];

    PGPKey *issuerKey = [self findKeyForKeyID:issuerKeyID];
    if (!issuerKey) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing issuer"}];
        }
        return NO;
    }

    return [self verifyData:signedData withSignature:signatureData usingKey:issuerKey error:error];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey error:(NSError * __autoreleasing *)error
{
    if (!publicKey || !signatureData || !signatureData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Invalid input data"}];
        }
        return NO;
    }

    id packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing signature"}];
        }
        return NO;
    }

    PGPSignaturePacket *signaturePacket = packet;
    BOOL verified = [signaturePacket verifyData:signedData withKey:publicKey userID:nil error:error];

    return verified;
}

- (BOOL) verifyData:(NSData *)signedDataPackets error:(NSError * __autoreleasing *)error
{
    // this is propably not the best solution when it comes to memory consumption
    // because literal data is copied more than once (first at parse phase, then when is come to build signature packet data
    // I belive this is unecessary but require more work. Schedule to v2.0
    @autoreleasepool {
        // search for signature packet
        NSMutableArray *accumulatedPackets = [NSMutableArray array];
        NSUInteger offset = 0;
        NSUInteger nextPacketOffset;
        //TODO: dont parse data here, get raw data and pass to verifyData:withsignature:
        while (offset < signedDataPackets.length) {

            PGPPacket *packet = [PGPPacketFactory packetWithData:signedDataPackets offset:offset nextPacketOffset:&nextPacketOffset];
            if (packet) {
                [accumulatedPackets addObject:packet];
            }

            offset += nextPacketOffset;
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
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing signature packet or literal data packet"}];
            }
            return NO;
        }

        // do not build signature, use data that was readed from signedDataPackets
        // to build final data and avoid unecesarry copying data dataWithBytesNoCopy:length:freeWhenDone: is used
        // signaturePacket and literalDataPacket is strong in this scope so will not be released
        // before verification process end.
        NSMutableData *signaturePacketData = [NSMutableData data];
        [signaturePacketData appendData:[NSData dataWithBytesNoCopy:(void *)signaturePacket.headerData.bytes length:signaturePacket.headerData.length freeWhenDone:NO]];
        [signaturePacketData appendData:[NSData dataWithBytesNoCopy:(void *)signaturePacket.bodyData.bytes length:signaturePacket.bodyData.length freeWhenDone:NO]];

        return [self verifyData:literalDataPacket.literalRawData withSignature:signaturePacketData error:error];
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
- (NSArray * __nullable) importKeysFromFile:(NSString * __nonnull)path allowDuplicates:(BOOL)allowDuplicates
{
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    
    return [self importKeysFromData:[NSData dataWithContentsOfFile:path] allowDuplicates:allowDuplicates];
}

- (NSArray * __nullable) importKeysFromData:(NSData * __nonnull)data allowDuplicates:(BOOL)allowDuplicates
{
    NSArray *loadedKeys = [self keysFromData:data];
    if (!allowDuplicates) {
        NSMutableSet *keysSet = [NSMutableSet setWithArray:self.keys];
        [keysSet addObjectsFromArray:loadedKeys];
        self.keys = [keysSet allObjects];
    } else {
        self.keys = [self.keys arrayByAddingObjectsFromArray:loadedKeys];
    }
    return loadedKeys;
}

- (BOOL) importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    NSArray *loadedKeys = [self keysFromFile:fullPath];
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

- (NSArray<PGPKey *> * __nullable) keysFromFile:(NSString * __nonnull)path
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
    
    return [self keysFromData:fileData];
}

- (NSArray * __nullable) keysFromData:(NSData * __nonnull)fileData
{
    NSAssert(fileData.length > 0, @"Empty data");

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

#pragma mark - Private

- (NSArray *) readPacketsFromData:(NSData *)keyringData
{
    NSMutableArray *accumulatedPackets = [NSMutableArray array];
    NSUInteger offset = 0;
    NSUInteger nextPacketOffset = 0;
    
    while (offset < keyringData.length) {
        
        PGPPacket *packet = [PGPPacketFactory packetWithData:keyringData offset:offset nextPacketOffset:&nextPacketOffset];
        if (packet) {
            [accumulatedPackets addObject:packet];
        }
        
        offset += nextPacketOffset;
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
        
        NSUInteger nextPacketOffset;
        PGPPacket *packet = [PGPPacketFactory packetWithData:messageData offset:offset nextPacketOffset:&nextPacketOffset];
        if (packet) {
            if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
                PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
                [keys addObject:key];
                [accumulatedPackets removeAllObjects];
            }
            [accumulatedPackets addObject:packet];
        }
        offset += nextPacketOffset;
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
        // propably unecessary since armore code care about \r\n or \n as newline sentence
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
