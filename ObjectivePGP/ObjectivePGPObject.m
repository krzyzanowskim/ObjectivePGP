//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "ObjectivePGPObject.h"
#import "PGPArmor.h"
#import "PGPCompressedPacket.h"
#import "PGPCryptoUtils.h"
#import "PGPKey+Private.h"
#import "PGPKey.h"
#import "PGPLiteralPacket.h"
#import "PGPMPI.h"
#import "PGPModificationDetectionCodePacket.h"
#import "PGPOnePassSignaturePacket.h"
#import "PGPPacketFactory.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignaturePacket.h"
#import "PGPPartialSubKey.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPUser.h"
#import "PGPUserIDPacket.h"
#import "NSMutableData+PGPUtils.h"
#import "NSArray+PGPUtils.h"

#import "PGPFoundation.h"
#import "PGPLogging.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ObjectivePGP ()

@property (strong, nonatomic, readwrite) NSArray<PGPKey *> *keys;

@end

@implementation ObjectivePGP

- (instancetype)init {
    if ((self = [super init])) {
        _keys = [NSMutableArray<PGPKey *> array];
    }
    return self;
}

#pragma mark - Search

- (NSArray<PGPKey *> *)findKeysForUserID:(nonnull NSString *)userID {
    return [self.keys pgp_objectsPassingTest:^BOOL(PGPKey *key, __unused BOOL *stop1) {
        let a = key.publicKey ? [key.publicKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, __unused NSUInteger idx, __unused BOOL *stop2) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        let b = key.secretKey ? [key.secretKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, __unused NSUInteger idx, __unused BOOL *stop2) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        return (a != NSNotFound) || (b != NSNotFound);
    }];
}

- (nullable PGPKey *)findKeyWithKeyID:(PGPKeyID *)searchKeyID {
    return [ObjectivePGP findKeyWithKeyID:searchKeyID in:self.keys];
}

+ (nullable PGPKey *)findKeyWithKeyID:(PGPKeyID *)searchKeyID in:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(searchKeyID, PGPKeyID);

    return [[keys pgp_objectsPassingTest:^BOOL(PGPKey *key, BOOL *stop) {
        // top-level keys
        __block BOOL found = (key.publicKey && PGPEqualObjects(key.publicKey.keyID, searchKeyID));
        if (!found) {
            found = (key.secretKey && PGPEqualObjects(key.secretKey.keyID,searchKeyID));
        }

        // subkeys
        if (!found && key.publicKey.subKeys.count > 0) {
            found = [key.publicKey.subKeys indexOfObjectPassingTest:^BOOL(PGPPartialSubKey *subkey, __unused NSUInteger idx, BOOL *stop2) {
                        *stop2 = PGPEqualObjects(subkey.keyID,searchKeyID);
                        return *stop2;
                    }] != NSNotFound;
        }

        if (!found && key.secretKey.subKeys.count > 0) {
            found = [key.secretKey.subKeys indexOfObjectPassingTest:^BOOL(PGPPartialSubKey *subkey, __unused NSUInteger idx, BOOL *stop2) {
                        *stop2 = PGPEqualObjects(subkey.keyID,searchKeyID);
                        return *stop2;
                    }] != NSNotFound;
        }

        *stop = found;
        return found;
    }] firstObject];
}

- (nullable PGPKey *)findKeyWithIdentifier:(NSString *)keyIdentifier {
    PGPAssertClass(keyIdentifier, NSString);

    if (keyIdentifier.length != 8 && keyIdentifier.length != 16) {
        PGPLogDebug(@"Invalid key identifier: %@", keyIdentifier);
        return nil;
    }

    BOOL useShortIdentifier = keyIdentifier.length == 8;

    // public
    for (PGPKey *key in self.keys) {
        if (key.publicKey) {
            let identifier = useShortIdentifier ? key.publicKey.keyID.shortIdentifier : key.publicKey.keyID.longIdentifier;
            if ([identifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                return key;
            }

            for (PGPPartialSubKey *subkey in key.publicKey.subKeys) {
                let subIdentifier = useShortIdentifier ? subkey.keyID.shortIdentifier : subkey.keyID.longIdentifier;
                if ([subIdentifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                    return key;
                }
            }
        }

        if (key.secretKey) {
            let identifier = useShortIdentifier ? key.secretKey.keyID.shortIdentifier : key.secretKey.keyID.longIdentifier;
            if ([identifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                return key;
            }

            for (PGPPartialSubKey *subkey in key.secretKey.subKeys) {
                let subIdentifier = useShortIdentifier ? subkey.keyID.shortIdentifier : subkey.keyID.longIdentifier;
                if ([subIdentifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                    return key;
                }
            }
        }
    }

    return nil;
}

#pragma mark - Save

- (BOOL)exportKeysOfType:(PGPPartialKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing *)error {
    let exportKeys = [NSMutableArray<PGPPartialKey *> array];
    for (PGPKey *key in self.keys) {
        if (type == PGPPartialKeyPublic && key.publicKey) {
            [exportKeys pgp_addObject:key.publicKey];
        }
        if (type == PGPPartialKeySecret && key.secretKey) {
            [exportKeys pgp_addObject:key.secretKey];
        }
    }
    return [self exportKeys:exportKeys toFile:path error:error];
}

- (BOOL)exportKeys:(NSArray<PGPPartialKey *> *)keys toFile:(NSString *)path error:(NSError * __autoreleasing *)error {
    NSParameterAssert(keys);
    PGPAssertClass(path, NSString);

    if (keys.count == 0) {
        return NO;
    }

    for (PGPPartialKey *key in keys) {
        if (![self appendKey:key toKeyring:path error:error]) {
            return NO;
        }
    }
    return YES;
}

- (BOOL)appendKey:(PGPPartialKey *)key toKeyring:(NSString *)path error:(NSError * __autoreleasing *)error {
    NSFileManager *fm = [NSFileManager defaultManager];

    if (!path) {
        return NO;
    }

    let keyData = [key export:error];
    if (!keyData) {
        return NO;
    }

    BOOL result = NO;
    if (![fm fileExistsAtPath:path]) {
        NSDictionary *attributes = nil;
#ifdef __IPHONE_OS_VERSION_MAX_ALLOWED
        attributes = @{ NSFileProtectionKey: NSFileProtectionComplete, NSFilePosixPermissions: @(0600) };
#else
        attributes = @{ NSFilePosixPermissions: @(0600) };
#endif
        result = [fm createFileAtPath:path contents:keyData attributes:attributes];
    } else {
        @try {
            NSFileHandle *fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:path];
            [fileHandle seekToEndOfFile];
            [fileHandle writeData:keyData];
            [fileHandle closeFile];
            result = YES;
        } @catch (NSException *exception) {
            result = NO;
        }
    }
    return result;
}

- (nullable NSData *)exportKey:(PGPKey *)key armored:(BOOL)armored {
    PGPAssertClass(key, PGPKey);

    NSError *exportError = nil;
    NSData *keyData = [key export:&exportError];
    if (!keyData || exportError) {
        PGPLogDebug(@"%@", exportError);
        return nil;
    }

    if (armored) {
        return [[PGPArmor armored:keyData as:PGPArmorTypePublicKey] dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        return keyData;
    }
    return nil;
}

#pragma mark - Delete

- (void)deleteKeys:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(keys, NSArray);

    let allKeys = [NSMutableArray<PGPKey *> arrayWithArray:self.keys];
    for (PGPKey *key in keys) {
        [allKeys removeObject:key];
    }
    self.keys = allKeys;
}

#pragma mark - Encrypt & Decrypt

- (nullable NSData *)decrypt:(NSData *)data passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    return [ObjectivePGP decrypt:data usingKeys:self.keys passphrase:passphrase verifySignature:YES error:error];
}

+ (nullable NSData *)decrypt:(NSData *)data usingKeys:(NSArray<PGPKey *> *)keys passphrase:(nullable NSString *)passphrase verifySignature:(BOOL)verifySignature error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(data, NSData);
    PGPAssertClass(keys, NSArray);

    // TODO: Decrypt all messages
    let binaryMessage = [ObjectivePGP convertArmoredMessage2BinaryBlocksWhenNecessary:data].firstObject;
    if (!binaryMessage) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Invalid message to decrypt." }];
        }
        return nil;
    }

    // parse packets
    var packets = [ObjectivePGP readPacketsFromData:binaryMessage];
    packets = [self decryptPackets:packets usingKeys:keys passphrase:passphrase error:error];

    let literalPacket = PGPCast([[packets pgp_objectsPassingTest:^BOOL(PGPPacket *packet, BOOL *stop) {
        return packet.tag == PGPLiteralDataPacketTag;
    }] firstObject], PGPLiteralPacket);

    // Plaintext is available if literalPacket is available
    let plaintextData = literalPacket.literalRawData;
    if (!plaintextData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Nothing to decrypt." }];
        }
        return nil;
    }

    // Verify
    if (verifySignature) {
        if (![self verify:binaryMessage withSignature:nil usingKeys:keys passphrase:passphrase error:error]) {
            if (error && !*error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Unable to verify." }];
            }
        }
    }

    return plaintextData;
}

+ (NSArray<PGPPacket *> *)decryptPackets:(NSArray<PGPPacket *> *)encryptedPackets usingKeys:(NSArray<PGPKey *> *)keys passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    PGPSecretKeyPacket * _Nullable decryptionSecretKeyPacket = nil; // last found secret key to used to decrypt
    let packets = [NSMutableArray arrayWithArray:encryptedPackets];

    // 1. search for valid and known (do I have specified key?) ESK
    PGPPublicKeyEncryptedSessionKeyPacket * _Nullable eskPacket = nil;
    for (PGPPacket *packet in packets) {
        if (packet.tag == PGPPublicKeyEncryptedSessionKeyPacketTag) {
            let pkESKPacket = PGPCast(packet, PGPPublicKeyEncryptedSessionKeyPacket);
            let decryptionKey = [self findKeyWithKeyID:pkESKPacket.keyID in:keys];
            if (!decryptionKey.secretKey) {
                continue;
            }

            decryptionSecretKeyPacket = PGPCast([decryptionKey.secretKey decryptionPacketForKeyID:pkESKPacket.keyID error:error], PGPSecretKeyPacket);
            if (!decryptionSecretKeyPacket) {
                continue;
            }

            // decrypt key with passphrase if encrypted
            if (decryptionSecretKeyPacket.isEncryptedWithPassphrase) {
                if (!passphrase) {
                    if (error) {
                        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseRequired userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Passphrase is required for a key." }];
                    }
                    return encryptedPackets;
                }

                decryptionSecretKeyPacket = [decryptionSecretKeyPacket decryptedWithPassphrase:PGPNN(passphrase) error:error];
                if (!decryptionSecretKeyPacket || (error && *error)) {
                    decryptionSecretKeyPacket = nil;
                    continue;
                }
            }
            eskPacket = pkESKPacket;
        }
    }

    if (error && *error) {
        return @[];
    }

    if (!eskPacket || !decryptionSecretKeyPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unable to decrypt. Invalid message." }];
        }
        return encryptedPackets;
    }

    PGPSymmetricAlgorithm sessionKeyAlgorithm = PGPSymmetricPlaintext; // default
    let sessionKeyData = [eskPacket decryptSessionKeyData:PGPNN(decryptionSecretKeyPacket) sessionKeyAlgorithm:&sessionKeyAlgorithm error:error];
    NSAssert(sessionKeyAlgorithm < PGPSymmetricMax, @"Invalid session key algorithm");

    if (!sessionKeyData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Missing session key" }];
        }
        return encryptedPackets;
    }

    // 2
    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag: {
                // decrypt PGPSymmetricallyEncryptedIntegrityProtectedDataPacket
                let symEncryptedDataPacket = PGPCast(packet, PGPSymmetricallyEncryptedIntegrityProtectedDataPacket);
                let decryptedPackets = [symEncryptedDataPacket decryptWithSecretKeyPacket:PGPNN(decryptionSecretKeyPacket) sessionKeyAlgorithm:sessionKeyAlgorithm sessionKeyData:sessionKeyData error:error];
                [packets addObjectsFromArray:decryptedPackets];
            } break;
            case PGPSymmetricallyEncryptedDataPacketTag: {
                let symEncryptedDataPacket = PGPCast(packet, PGPSymmetricallyEncryptedDataPacket);
                let decryptedPackets = [symEncryptedDataPacket decryptWithSecretKeyPacket:PGPNN(decryptionSecretKeyPacket) sessionKeyAlgorithm:sessionKeyAlgorithm sessionKeyData:sessionKeyData error:error];
                [packets addObjectsFromArray:decryptedPackets];
            }
            default:
                break;
        }
    }

    if (packets.count == 0) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Unable to find valid data to decrypt." }];
        }
        return encryptedPackets;
    }

    return packets;
}

+ (nullable NSData *)encrypt:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPKey *> *)keys armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error {
    return [ObjectivePGP encrypt:dataToEncrypt usingKeys:keys signWithKey:nil passphrase:nil armored:armored error:error];
}

+ (nullable NSData *)encrypt:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPKey *> *)keys signWithKey:(nullable PGPKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error {
    let publicPartialKeys = [NSMutableArray<PGPPartialKey *> array];
    for (PGPKey *key in keys) {
        [publicPartialKeys pgp_addObject:key.publicKey];
    }

    let encryptedMessage = [NSMutableData data];

    // PGPPublicKeyEncryptedSessionKeyPacket goes here
    let preferredSymmeticAlgorithm = [PGPPartialKey preferredSymmetricAlgorithmForKeys:publicPartialKeys];

    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:preferredSymmeticAlgorithm];
    let sessionKeyData = [PGPCryptoUtils randomData:keySize];

    for (PGPPartialKey *publicPartialKey in publicPartialKeys) {
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        // Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
        // ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.

        // ESK
        let encryptionKeyPacket = PGPCast([publicPartialKey encryptionKeyPacket:error], PGPPublicKeyPacket);
        if (!encryptionKeyPacket) {
            continue;
        }

        // var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
        let eskKeyPacket = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] init];
        eskKeyPacket.keyID = encryptionKeyPacket.keyID;
        eskKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.publicKeyAlgorithm;
        BOOL encrypted = [eskKeyPacket encrypt:encryptionKeyPacket sessionKeyData:sessionKeyData sessionKeyAlgorithm:preferredSymmeticAlgorithm error:error];
        if (!encrypted || (error && *error)) {
            PGPLogDebug(@"Failed encrypt Symmetric-key Encrypted Session Key packet. Error: %@", error ? *error : @"Unknown");
            return nil;
        }
        [encryptedMessage pgp_appendData:[eskKeyPacket export:error]];
        if (error && *error) {
            PGPLogDebug(@"Missing literal data. Error: %@", error ? *error : @"Unknown");
            return nil;
        }

        //TODO: find the compression type most common to the used keys
    }

    NSData *content;
    // sign data if requested
    if (signKey) {
        content = [self sign:dataToEncrypt usingKey:signKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:NO error:error];
    } else {
        // Prepare literal packet
        let literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToEncrypt];
        literalPacket.filename = nil;
        literalPacket.timestamp = NSDate.date;

        let literalPacketData = [literalPacket export:error];
        if (error && *error) {
            PGPLogDebug(@"Missing literal packet data. Error: %@", *error);
            return nil;
        }

        //FIXME: do not use hardcoded value for compression type
        let compressedPacket = [[PGPCompressedPacket alloc] initWithData:literalPacketData type:PGPCompressionZLIB];
        content = [compressedPacket export:error];
    }

    if (!content || (error && *error)) {
        return nil;
    }

    let symEncryptedDataPacket = [[PGPSymmetricallyEncryptedIntegrityProtectedDataPacket alloc] init];
    [symEncryptedDataPacket encrypt:content symmetricAlgorithm:preferredSymmeticAlgorithm sessionKeyData:sessionKeyData error:error];

    if (error && *error) {
        return nil;
    }

    [encryptedMessage pgp_appendData:[symEncryptedDataPacket export:error]];
    if (error && *error) {
        return nil;
    }

    if (armored) {
        return [[PGPArmor armored:encryptedMessage as:PGPArmorTypeMessage] dataUsingEncoding:NSUTF8StringEncoding];
    }

    return encryptedMessage;
}

#pragma mark - Sign & Verify

+(nullable NSData *)sign:(NSData *)dataToSign usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing *)error {
    // TODO: configurable defaults for prefered hash
    return [ObjectivePGP sign:dataToSign usingKey:key passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:detached error:error];
}

+ (nullable NSData *)sign:(NSData *)dataToSign usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase hashAlgorithm:(PGPHashAlgorithm)preferedHashAlgorithm detached:(BOOL)detached error:(NSError * __autoreleasing *)error {
    PGPAssertClass(dataToSign, NSData);
    PGPAssertClass(key, PGPKey);

    let signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument hashAlgorithm:preferedHashAlgorithm];
    if (![signaturePacket signData:dataToSign withKey:key subKey:nil passphrase:passphrase userID:nil error:error]) {
        PGPLogDebug(@"Can't sign data");
        return nil;
    }

    NSError * _Nullable exportError = nil;
    let _Nullable signaturePacketData = [signaturePacket export:&exportError];
    if (exportError) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Error on export packet" }];
        }
        return nil;
    }

    // Signed Message :- Signature Packet, Literal Message
    NSMutableData *signedMessage = [NSMutableData data];
    if (!detached) {
        // OnePass
        let onePassPacket = [[PGPOnePassSignaturePacket alloc] init];
        onePassPacket.signatureType = signaturePacket.type;
        onePassPacket.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
        onePassPacket.hashAlgorith = signaturePacket.hashAlgoritm;

        onePassPacket.keyID = PGPNN([signaturePacket issuerKeyID]);

        onePassPacket.isNested = YES;
        NSError * _Nullable onePassExportError = nil;
        [signedMessage pgp_appendData:[onePassPacket export:&onePassExportError]];
        if (onePassExportError) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing one passphrase data" }];
            }
            return nil;
        }

        // Literal
        PGPLiteralPacket *literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToSign];
        literalPacket.filename = nil;
        literalPacket.timestamp = [NSDate date];

        NSError *literalExportError = nil;
        [signedMessage pgp_appendData:[literalPacket export:&literalExportError]];
        if (literalExportError) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing literal data" }];
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
        //        [signedMessage pgp_appendData:[compressedPacket exportPacket:&compressedExportError]];
        //        NSAssert(!compressedExportError, @"Missing compressed data");
        //        if (compressedExportError) {
        //            if (error) {
        //                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing compressed data"}];
        //            }
        //            return nil;
        //        }
    }
    [signedMessage pgp_appendData:signaturePacketData];
    return signedMessage;
}

- (BOOL)verify:(NSData *)signedData withSignature:(nullable NSData *)detachedSignature passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    return [self.class verify:signedData withSignature:detachedSignature usingKeys:self.keys passphrase:passphrase error:error];
}

+ (BOOL)verify:(NSData *)signedData withSignature:(nullable NSData *)detachedSignature usingKeys:(NSArray<PGPKey *> *)keys passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(signedData, NSData);

    let binaryMessages = [ObjectivePGP convertArmoredMessage2BinaryBlocksWhenNecessary:signedData];
    // TODO: Process all messages
    let binarySignedData = binaryMessages.count > 0 ? binaryMessages.firstObject : nil;
    if (!binarySignedData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidMessage userInfo:@{ NSLocalizedDescriptionKey: @"Invalid input data" }];
        }
        return NO;
    }

    // Use detached signature if provided.
    // In that case treat input data as blob to be verified with the signature. Don't parse it.
    if (detachedSignature) {
        let binarydetachedSignature = [ObjectivePGP convertArmoredMessage2BinaryBlocksWhenNecessary:detachedSignature].firstObject;
        if (binarydetachedSignature) {
            let packet = [PGPPacketFactory packetWithData:binarydetachedSignature offset:0 consumedBytes:nil];
            let signaturePacket = PGPCast(packet, PGPSignaturePacket);
            let issuerKeyID = signaturePacket.issuerKeyID;
            if (issuerKeyID) {
                let issuerKey = [self findKeyWithKeyID:issuerKeyID in:keys];
                return [signaturePacket verifyData:binarySignedData publicKey:issuerKey error:error];
            }
        }
        return NO;
    }

    // Otherwise treat input data as PGP Message and process for literal data.

    // Propably not the best solution when it comes to memory consumption.
    // Literal data is copied more than once (first at parse phase, then when is come to build signature packet data.
    // I belive this is unecessary but require more work. Schedule to v2.0.

    // search for signature packet
    var accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger offset = 0;
    NSUInteger consumedBytes = 0;

    @autoreleasepool {
        // TODO: don't parse data here, get raw data and pass to verify:withsignature:
        while (offset < binarySignedData.length) {
            let packet = [PGPPacketFactory packetWithData:binarySignedData offset:offset consumedBytes:&consumedBytes];
            [accumulatedPackets pgp_addObject:packet];
            offset += consumedBytes;
        }
    }

    //TODO: use a block to get the passphrase for decryption per key
    //Try to decrypt first, in case of encrypted message inside
    //Not every message needs decryption though! Check for ESK to reason about it
    BOOL isEncrypted = [[accumulatedPackets pgp_objectsPassingTest:^BOOL(PGPPacket *packet, BOOL *stop) {
        BOOL found = packet.tag == PGPPublicKeyEncryptedSessionKeyPacketTag;
        *stop = found;
        return found;
    }] firstObject] != nil;

    if (isEncrypted) {
        NSError *decryptError = nil;
        accumulatedPackets = [[self.class decryptPackets:accumulatedPackets usingKeys:keys passphrase:passphrase error:&decryptError] mutableCopy];
        if (decryptError) {
            if (error) {
                *error = [decryptError copy];
            }
            return NO;
        }
    }

    PGPSignaturePacket * _Nullable signaturePacket = nil;
    PGPLiteralPacket * _Nullable literalPacket = nil;
    for (PGPPacket *packet in accumulatedPackets) {
        switch (packet.tag) {
            case PGPCompressedDataPacketTag:
            case PGPOnePassSignaturePacketTag:
                // ignore here
                break;
            case PGPLiteralDataPacketTag:
                literalPacket = PGPCast(packet, PGPLiteralPacket);
                break;
            case PGPSignaturePacketTag:
                signaturePacket = PGPCast(packet, PGPSignaturePacket);
                break;
            default:
                break;
        }
    }

    if (!signaturePacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorNotSigned userInfo:@{ NSLocalizedDescriptionKey: @"Message is not signed." }];
        }
        return NO;
    }

    if (!literalPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Message is not valid. Missing literal data." }];
        }
        return NO;
    }

    let signedLiteralData = literalPacket.literalRawData;
    if (signedLiteralData && (!error || (error && *error == nil))) {
        let issuerKeyID = signaturePacket.issuerKeyID;
        if (issuerKeyID) {
            let issuerKey = [self findKeyWithKeyID:issuerKeyID in:keys];
            if (!issuerKey) {
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorInvalidSignature userInfo:@{ NSLocalizedDescriptionKey: @"Unable to check signature. No public key." }];
                }
                return NO;
            }
            return [signaturePacket verifyData:signedLiteralData publicKey:issuerKey error:error];
        }
    }
    return NO;
}

#pragma mark - Parse keyring

- (void)importKeys:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(keys, NSArray);

    for (PGPKey *key in keys) {
        self.keys = [ObjectivePGP addOrUpdatePartialKey:key.secretKey inContainer:self.keys];
        self.keys = [ObjectivePGP addOrUpdatePartialKey:key.publicKey inContainer:self.keys];
    }
}

- (BOOL)importKey:(NSString *)keyIdentifier fromFile:(NSString *)path {
    let fullPath = [path stringByExpandingTildeInPath];

    let loadedKeys = [self.class readKeysFromFile:fullPath];
    if (loadedKeys.count == 0) {
        return NO;
    }

    let foundKey = [[loadedKeys pgp_objectsPassingTest:^BOOL(PGPKey *key, BOOL *stop) {
        *stop = PGPEqualObjects(key.publicKey.keyID.shortIdentifier.uppercaseString, keyIdentifier.uppercaseString) || PGPEqualObjects(key.secretKey.keyID.shortIdentifier.uppercaseString, keyIdentifier.uppercaseString) ||
                PGPEqualObjects(key.publicKey.keyID.longIdentifier.uppercaseString, keyIdentifier.uppercaseString) || PGPEqualObjects(key.secretKey.keyID.longIdentifier.uppercaseString, keyIdentifier.uppercaseString);
        return *stop;

    }] firstObject];

    if (!foundKey) {
        return NO;
    }

    self.keys = [self.keys arrayByAddingObject:foundKey];

    return YES;
}

+ (NSArray<PGPKey *> *)readKeysFromFile:(NSString *)path {
    NSString *fullPath = [path stringByExpandingTildeInPath];

    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:&isDirectory] || isDirectory) {
        return @[];
    }

    NSError * _Nullable error = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe | NSDataReadingUncached error:&error];
    if (!fileData || error) {
        return @[];
    }

    return [self readKeysFromData:fileData];
}

+ (NSArray<PGPKey *> *)readKeysFromData:(NSData *)fileData {
    PGPAssertClass(fileData, NSData);
    
    var keys = [NSArray<PGPKey *> array];

    if (fileData.length == 0) {
        PGPLogError(@"Empty input data");
        return keys;
    };

    let binRingData = [ObjectivePGP convertArmoredMessage2BinaryBlocksWhenNecessary:fileData];
    if (!binRingData || binRingData.count == 0) {
        PGPLogError(@"Invalid input data");
        return keys;
    }

    for (NSData *data in binRingData) {
        let readPartialKeys = [ObjectivePGP readPartialKeysFromData:data];
        for (PGPPartialKey *key in readPartialKeys) {
            keys = [ObjectivePGP addOrUpdatePartialKey:key inContainer:keys];
        }
    }

    return keys;
}

#pragma mark - Private

+ (NSArray<PGPPacket *> *)readPacketsFromData:(NSData *)keyringData {
    PGPAssertClass(keyringData, NSData);

    if (keyringData.length == 0) {
        return @[];
    }

    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger offset = 0;
    NSUInteger consumedBytes = 0;

    while (offset < keyringData.length) {
        let packet = [PGPPacketFactory packetWithData:keyringData offset:offset consumedBytes:&consumedBytes];
        [accumulatedPackets pgp_addObject:packet];

        // corrupted data. Move by one byte in hope we find some packet there, or EOF.
        if (consumedBytes == 0) {
            offset++;
        }
        offset += consumedBytes;
    }

    return accumulatedPackets;
}

// Add or update compound key. Returns updated set.
+ (NSArray<PGPKey *> *)addOrUpdatePartialKey:(nullable PGPPartialKey *)key inContainer:(NSArray<PGPKey *> *)keys {
    if (!key) {
        return keys;
    }

    NSMutableArray *updatedContainer = [NSMutableArray<PGPKey *> arrayWithArray:keys];

    PGPKey *foundCompoundKey = nil;
    for (PGPKey *searchKey in keys) {
        if (PGPEqualObjects(searchKey.publicKey.keyID,key.keyID) || PGPEqualObjects(searchKey.secretKey.keyID,key.keyID)) {
            foundCompoundKey = searchKey;
            break;
        }
    }

    if (!foundCompoundKey) {
        let compoundKey = [[PGPKey alloc] initWithSecretKey:(key.type == PGPPartialKeySecret ? key : nil) publicKey:(key.type == PGPPartialKeyPublic ? key : nil)];
        [updatedContainer addObject:compoundKey];
    } else {
        if (key.type == PGPPartialKeyPublic) {
            foundCompoundKey.publicKey = key;
        }
        if (key.type == PGPPartialKeySecret) {
            foundCompoundKey.secretKey = key;
        }
    }

    return updatedContainer;
}

+ (NSArray<PGPPartialKey *> *)readPartialKeysFromData:(NSData *)messageData {
    let partialKeys = [NSMutableArray<PGPPartialKey *> array];
    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger position = 0;
    NSUInteger consumedBytes = 0;

    while (position < messageData.length) {
        @autoreleasepool {
            let packet = [PGPPacketFactory packetWithData:messageData offset:position consumedBytes:&consumedBytes];
            if (!packet) {
                position += (consumedBytes > 0) ? consumedBytes : 1;
                continue;
            }

            if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
                let partialKey = [[PGPPartialKey alloc] initWithPackets:accumulatedPackets];
                [partialKeys addObject:partialKey];
                [accumulatedPackets removeAllObjects];
            }

            [accumulatedPackets pgp_addObject:packet];
            position += consumedBytes;
        }
    }

    if (accumulatedPackets.count > 1) {
        let key = [[PGPPartialKey alloc] initWithPackets:accumulatedPackets];
        [partialKeys addObject:key];
        [accumulatedPackets removeAllObjects];
    }

    return partialKeys;
}

+ (NSArray<NSData *> *)convertArmoredMessage2BinaryBlocksWhenNecessary:(NSData *)binOrArmorData {
    let binRingData = binOrArmorData;
    // detect if armored, check for string -----BEGIN PGP
    if ([PGPArmor isArmoredData:binRingData]) {
        NSError * _Nullable deadmorError = nil;
        var armoredString = [[NSString alloc] initWithData:binRingData encoding:NSUTF8StringEncoding];

        // replace \n to \r\n
        // propably unecessary since armore code care about \r\n or \n as newline sentence
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"];

        let extractedBlocks = [[NSMutableArray<NSString *> alloc] init];
        let regex = [[NSRegularExpression alloc] initWithPattern:@"(-----)(BEGIN|END)[ ](PGP)[A-Z ]*(-----)" options:NSRegularExpressionDotMatchesLineSeparators error:nil];
        __block NSInteger offset = 0;
        [regex enumerateMatchesInString:armoredString options:NSMatchingReportCompletion range:NSMakeRange(0, armoredString.length) usingBlock:^(NSTextCheckingResult *_Nullable result, __unused NSMatchingFlags flags, __unused BOOL *stop) {
            let substring = [armoredString substringWithRange:result.range];
            if ([substring containsString:@"END"]) {
                NSInteger endIndex = result.range.location + result.range.length;
                [extractedBlocks addObject:[armoredString substringWithRange:NSMakeRange(offset, endIndex - offset)]];
            } else if ([substring containsString:@"BEGIN"]) {
                offset = result.range.location;
            }
        }];

        let extractedData = [[NSMutableArray<NSData *> alloc] init];
        for (NSString *extractedString in extractedBlocks) {
            let armodedData = [PGPArmor readArmored:extractedString error:&deadmorError];
            if (deadmorError) {
                return @[];
            }

            [extractedData pgp_addObject:armodedData];
        }
        return extractedData;
    }
    return @[binRingData];
}

@end

NS_ASSUME_NONNULL_END

