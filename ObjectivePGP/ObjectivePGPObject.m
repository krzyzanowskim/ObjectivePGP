//
//  ObjectivePGPObject.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 03/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
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
#import "PGPSymmetricallyEncryptedIntegrityProtectedDataPacket.h"
#import "PGPUser.h"
#import "PGPUserIDPacket.h"
#import "NSMutableData+PGPUtils.h"
#import "NSMutableArray+PGPUtils.h"

#import "PGPFoundation.h"
#import "PGPLogging.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@interface ObjectivePGP ()

@property (strong, nonatomic, readwrite) NSSet<PGPKey *> *keys;

@end

@implementation ObjectivePGP

- (instancetype)init {
    if ((self = [super init])) {
        _keys = [NSMutableSet<PGPKey *> set];
    }
    return self;
}

#pragma mark - Search

- (NSSet<PGPKey *> *)findKeysForUserID:(nonnull NSString *)userID {
    return [self.keys objectsPassingTest:^BOOL(PGPKey *key, __unused BOOL *stop1) {
        let a = key.publicKey ? [key.publicKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, __unused NSUInteger idx, __unused BOOL *stop2) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        let b = key.secretKey ? [key.secretKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, __unused NSUInteger idx, __unused BOOL *stop2) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        return (a != NSNotFound) || (b != NSNotFound);
    }];
}

- (nullable PGPKey *)findKeyForKeyID:(PGPKeyID *)searchKeyID {
    PGPAssertClass(searchKeyID, PGPKeyID);

    return [[self.keys objectsPassingTest:^BOOL(PGPKey *key, BOOL *stop) {
        // top-level keys
        __block BOOL found = (key.publicKey && [key.publicKey.keyID isEqual:searchKeyID]);
        if (!found) {
            found = (key.secretKey && [key.secretKey.keyID isEqual:searchKeyID]);
        }

        // subkeys
        if (!found && key.publicKey.subKeys.count > 0) {
            found = [key.publicKey.subKeys indexOfObjectPassingTest:^BOOL(PGPPartialSubKey *subkey, __unused NSUInteger idx, BOOL *stop2) {
                        *stop2 = [subkey.keyID isEqual:searchKeyID];
                        return *stop2;
                    }] != NSNotFound;
        }

        if (!found && key.secretKey.subKeys.count > 0) {
            found = [key.secretKey.subKeys indexOfObjectPassingTest:^BOOL(PGPPartialSubKey *subkey, __unused NSUInteger idx, BOOL *stop2) {
                        *stop2 = [subkey.keyID isEqual:searchKeyID];
                        return *stop2;
                    }] != NSNotFound;
        }

        *stop = found;
        return found;
    }] anyObject];
}

// TODO: rename to getKeyForFingerprint or something
- (nullable PGPKey *)findKeyForIdentifier:(NSString *)keyIdentifier {
    PGPAssertClass(keyIdentifier, NSString);

    if (keyIdentifier.length != 8 && keyIdentifier.length != 16) {
        PGPLogDebug(@"Invalid key identifier: %@", keyIdentifier);
        return nil;
    }

    BOOL useShortIdentifier = keyIdentifier.length == 8;

    // public
    for (PGPKey *key in self.keys) {
        if (key.publicKey) {
            let identifier = useShortIdentifier ? key.publicKey.keyID.shortKeyString : key.publicKey.keyID.longKeyString;
            if ([identifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                return key;
            }

            for (PGPPartialSubKey *subkey in key.publicKey.subKeys) {
                let subIdentifier = useShortIdentifier ? subkey.keyID.shortKeyString : subkey.keyID.longKeyString;
                if ([subIdentifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                    return key;
                }
            }
        }

        if (key.secretKey) {
            let identifier = useShortIdentifier ? key.secretKey.keyID.shortKeyString : key.secretKey.keyID.longKeyString;
            if ([identifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                return key;
            }

            for (PGPPartialSubKey *subkey in key.secretKey.subKeys) {
                let subIdentifier = useShortIdentifier ? subkey.keyID.shortKeyString : subkey.keyID.longKeyString;
                if ([subIdentifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                    return key;
                }
            }
        }
    }

    return nil;
}

#pragma mark - Save

- (BOOL)exportKeysOfType:(PGPPartialKeyType)type toFile:(NSString *)path error:(NSError *__autoreleasing *)error {
    let exportKeys = [NSMutableArray<PGPPartialKey *> array];
    for (PGPKey *key in self.keys) {
        if (type == PGPPartialKeyPublic && key.publicKey) {
            [exportKeys addObject:key.publicKey];
        }
        if (type == PGPPartialKeySecret && key.secretKey) {
            [exportKeys addObject:key.secretKey];
        }
    }
    return [self exportKeys:exportKeys toFile:path error:error];
}

- (BOOL)exportKeys:(NSArray<PGPPartialKey *> *)keys toFile:(NSString *)path error:(NSError *__autoreleasing *)error {
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

- (BOOL)appendKey:(PGPPartialKey *)key toKeyring:(NSString *)path error:(NSError *__autoreleasing *)error {
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
        return [PGPArmor armoredData:keyData as:PGPArmorTypePublicKey];
    } else {
        return keyData;
    }
    return nil;
}

#pragma mark - Delete

- (void)deleteKeys:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(keys, NSArray);

    let allKeys = [NSMutableSet<PGPKey *> setWithSet:self.keys];
    for (PGPKey *key in keys) {
        [allKeys removeObject:key];
    }
    self.keys = allKeys;
}

#pragma mark - Encrypt & Decrypt

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError *__autoreleasing *)error {
    return [self decryptData:messageDataToDecrypt passphrase:passphrase verifyWithKey:nil signed:nil valid:nil integrityProtected:nil error:error];
}

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithKey:(nullable PGPKey *)key signed:(nullable BOOL *)isSigned valid:(nullable BOOL *)isValid integrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError *__autoreleasing _Nullable *)error {
    PGPAssertClass(messageDataToDecrypt, NSData);
    let binaryMessages = [self convertArmoredMessage2BinaryBlocksWhenNecessary:messageDataToDecrypt];

    // decrypt first message only
    let binaryMessageToDecrypt = binaryMessages.count > 0 ? binaryMessages.firstObject : nil;
    if (!binaryMessageToDecrypt) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Invalid input data" }];
        }
        return nil;
    }

    // parse packets
    var packets = [self readPacketsFromData:binaryMessageToDecrypt];

    PGPSymmetricAlgorithm sessionKeyAlgorithm = PGPSymmetricPlaintext;
    PGPSecretKeyPacket *decryptionSecretKeyPacket = nil; // last found secret key to used to decrypt

    // 1. search for valid and known (do I have specified key?) ESK
    PGPPublicKeyEncryptedSessionKeyPacket *eskPacket = nil;
    for (PGPPacket *packet in packets) {
        if (packet.tag == PGPPublicKeyEncryptedSessionKeyPacketTag) {
            let pkESKPacket = PGPCast(packet, PGPPublicKeyEncryptedSessionKeyPacket);
            let decryptionKey = [self findKeyForKeyID:pkESKPacket.keyID];
            if (!decryptionKey.secretKey) {
                continue;
            }

            decryptionSecretKeyPacket = PGPCast([decryptionKey.secretKey decryptionKeyPacketWithID:pkESKPacket.keyID error:error], PGPSecretKeyPacket);
            if (!decryptionSecretKeyPacket) {
                continue;
            }

            // decrypt key with passphrase if encrypted
            if (decryptionSecretKeyPacket.isEncryptedWithPassphrase) {
                if (!passphrase) {
                    if (error) {
                        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseRequired userInfo:@{ NSLocalizedDescriptionKey: @"Passphrase is required for a key" }];
                    }
                    return nil;
                }

                decryptionSecretKeyPacket = [decryptionSecretKeyPacket decryptedKeyPacket:passphrase error:error];
                if (!decryptionSecretKeyPacket || (error && *error)) {
                    decryptionSecretKeyPacket = nil;
                    continue;
                }
            }
            eskPacket = pkESKPacket;
        }
    }

    if (error && *error) {
        return nil;
    }

    if (!eskPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Valid PublicKeyEncryptedSessionKeyPacket not found" }];
        }
        return nil;
    }

    if (!decryptionSecretKeyPacket) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unable to find valid secret key" }];
        }
        return nil;
    }

    let sessionKeyData = [eskPacket decryptSessionKeyData:decryptionSecretKeyPacket sessionKeyAlgorithm:&sessionKeyAlgorithm error:error];
    NSAssert(sessionKeyAlgorithm > 0, @"Invalid session key algorithm");

    NSAssert(sessionKeyData, @"Missing session key data");
    if (!sessionKeyData) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Missing session key data" }];
        }
        return nil;
    }

    // 2
    for (PGPPacket *packet in packets) {
        switch (packet.tag) {
            case PGPSymmetricallyEncryptedIntegrityProtectedDataPacketTag: {
                // decrypt PGPSymmetricallyEncryptedIntegrityProtectedDataPacket
                let symEncryptedDataPacket = PGPCast(packet, PGPSymmetricallyEncryptedIntegrityProtectedDataPacket);
                packets = [symEncryptedDataPacket decryptWithSecretKeyPacket:decryptionSecretKeyPacket sessionKeyAlgorithm:sessionKeyAlgorithm sessionKeyData:sessionKeyData isIntegrityProtected:isIntegrityProtected error:error];
            } break;
            default:
                break;
        }
    }

    if (packets.count == 0) {
        return nil;
    }

    PGPLiteralPacket * _Nullable literalPacket = nil;
    PGPSignaturePacket * _Nullable signaturePacket = nil;
    for (PGPPacket *packet in packets) {
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
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{ NSLocalizedDescriptionKey: @"Unknown packet (expected literal or compressed)" }];
                }
                return nil;
        }
    }

    BOOL dataIsSigned = signaturePacket != nil;
    if (isSigned) { *isSigned = dataIsSigned; }

    // available if literalPacket is available
    let _Nullable plaintextData = literalPacket.literalRawData;
    if (!plaintextData) {
        return nil;
    }

    BOOL dataIsValid = NO;
    if (signaturePacket && key.publicKey) {
        let signatureData = [signaturePacket export:error];
        if (signatureData) {
            dataIsValid = [self verifyData:plaintextData withSignature:signatureData usingKey:key error:nil];
        }
    }
    if (isValid) { *isValid = dataIsValid; }

    return plaintextData;
}

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPKey *> *)keys armored:(BOOL)armored error:(NSError *__autoreleasing _Nullable *)error {
    return [self encryptData:dataToEncrypt usingKeys:keys signWithKey:nil passphrase:nil armored:armored error:error];
}

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPKey *> *)keys signWithKey:(nullable PGPKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError *__autoreleasing _Nullable *)error {
    let publicKeys = [NSMutableArray<PGPPartialKey *> array];
    for (PGPKey *key in keys) {
        [publicKeys addObject:key.publicKey];
    }

    let encryptedMessage = [NSMutableData data];

    // PGPPublicKeyEncryptedSessionKeyPacket goes here
    let preferredSymmeticAlgorithm = [PGPPartialKey preferredSymmetricAlgorithmForKeys:publicKeys];

    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:preferredSymmeticAlgorithm];
    uint8_t buf[keySize];
    if (SecRandomCopyBytes(kSecRandomDefault, keySize, buf) == -1) {
        //TODO: error
        return nil;
    }

    let sessionKeyData = [NSMutableData dataWithBytes:buf length:keySize];

    for (PGPPartialKey *publicKey in publicKeys) {
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        // Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
        // ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.

        // ESK
        let encryptionKeyPacket = PGPCast([publicKey encryptionKeyPacket:error], PGPPublicKeyPacket);
        if (!encryptionKeyPacket) {
            continue;
        }

        // var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
        PGPPublicKeyEncryptedSessionKeyPacket *eskKeyPacket = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] init];
        eskKeyPacket.keyID = encryptionKeyPacket.keyID;
        eskKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.publicKeyAlgorithm;
        [eskKeyPacket encrypt:encryptionKeyPacket sessionKeyData:sessionKeyData sessionKeyAlgorithm:preferredSymmeticAlgorithm error:error];
        PGPLogWarning(@"Missing literal data");
        if (error && *error) {
            return nil;
        }
        [encryptedMessage pgp_appendData:[eskKeyPacket export:error]];
        if (error && *error) {
            return nil;
        }
    }

    NSData *content;
    // sign data if requested
    if (signKey) {
        content = [self signData:dataToEncrypt usingKey:signKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:NO error:error];
        if (error && *error) {
            return nil;
        }

    } else {
        // Prepare literal packet
        let literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToEncrypt];
        literalPacket.filename = nil;
        literalPacket.timestamp = [NSDate date];
        PGPLogWarning(@"Missing literal data");
        if (error && *error) {
            return nil;
        }
        let literalPacketData = [literalPacket export:error];
        if (error && *error) {
            return nil;
        }

        let compressedPacket = [[PGPCompressedPacket alloc] initWithData:literalPacketData type:PGPCompressionBZIP2];
        content = [compressedPacket export:error];
        if (error && *error) {
            return nil;
        }
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
        return [PGPArmor armoredData:encryptedMessage as:PGPArmorTypeMessage];
    }

    return encryptedMessage;
}

#pragma mark - Sign & Verify

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError *__autoreleasing *)error {
    // TODO: configurable defaults for prefered hash
    return [self signData:dataToSign usingKey:key passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:detached error:error];
}

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPKey *)key passphrase:(nullable NSString *)passphrase hashAlgorithm:(PGPHashAlgorithm)preferedHashAlgorithm detached:(BOOL)detached error:(NSError *__autoreleasing *)error {
    PGPAssertClass(dataToSign, NSData);
    PGPAssertClass(key, PGPKey);

    let signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument hashAlgorithm:preferedHashAlgorithm];
    if (![signaturePacket signData:dataToSign withKey:key subKey:nil passphrase:passphrase userID:nil error:error]) {
        PGPLogDebug(@"Can't sign data");
        return nil;
    }

    NSError *exportError = nil;
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
        PGPOnePassSignaturePacket *onePassPacket = [[PGPOnePassSignaturePacket alloc] init];
        onePassPacket.signatureType = signaturePacket.type;
        onePassPacket.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
        onePassPacket.hashAlgorith = signaturePacket.hashAlgoritm;

        onePassPacket.keyID = [signaturePacket issuerKeyID];

        onePassPacket.notNested = YES;
        NSError *onePassExportError = nil;
        [signedMessage pgp_appendData:[onePassPacket export:&onePassExportError]];
        NSAssert(!onePassExportError, @"Missing one passphrase data");
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
        NSAssert(!literalExportError, @"Missing literal data");
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

- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError *__autoreleasing _Nullable *)error {
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(signatureData, NSData);

    // search for key in keys
    let packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        PGPLogWarning(@"Missing key signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing signature packet" }];
        }
        return NO;
    }

    let signaturePacket = PGPCast(packet, PGPSignaturePacket);
    if (!signaturePacket) {
        return NO;
    }

    let issuerKeyID = [signaturePacket issuerKeyID];

    let issuerKey = [self findKeyForKeyID:issuerKeyID];
    if (!issuerKey) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing issuer" }];
        }
        return NO;
    }

    return [self verifyData:signedData withSignature:signatureData usingKey:issuerKey error:error];
}

- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)key error:(NSError *__autoreleasing _Nullable *)error {
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(key, PGPKey);

    let packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing signature" }];
        }
        return NO;
    }

    let signaturePacket = PGPCast(packet, PGPSignaturePacket);
    if (!signaturePacket) {
        return NO;
    }
    BOOL verified = [signaturePacket verifyData:signedData withKey:key userID:nil error:error];

    return verified;
}

- (BOOL)verifyData:(NSData *)signedDataPackets error:(NSError *__autoreleasing *)error {
    // this is propably not the best solution when it comes to memory consumption
    // because literal data is copied more than once (first at parse phase, then when is come to build signature packet data
    // I belive this is unecessary but require more work. Schedule to v2.0
    @autoreleasepool {
        // search for signature packet
        let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
        NSUInteger offset = 0;
        NSUInteger nextPacketOffset;
        // TODO: dont parse data here, get raw data and pass to verifyData:withsignature:
        while (offset < signedDataPackets.length) {
            let packet = [PGPPacketFactory packetWithData:signedDataPackets offset:offset nextPacketOffset:&nextPacketOffset];
            [accumulatedPackets pgp_addObject:packet];

            offset += nextPacketOffset;
        }

        PGPSignaturePacket *signaturePacket = nil;
        PGPLiteralPacket *literalDataPacket = nil;

        for (PGPPacket *packet in accumulatedPackets) {
            if (packet.tag == PGPSignaturePacketTag) {
                signaturePacket = PGPCast(packet, PGPSignaturePacket);
            }
            if (packet.tag == PGPLiteralDataPacketTag) {
                literalDataPacket = PGPCast(packet, PGPLiteralPacket);
            }
        }

        NSAssert(signaturePacket && literalDataPacket, @"Missing signature packet or literal data packet");
        if (!signaturePacket || !literalDataPacket) {
            if (error) {
                *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{ NSLocalizedDescriptionKey: @"Missing signature packet or literal data packet" }];
            }
            return NO;
        }

        let signaturePacketData = [signaturePacket export:error];

        if (signaturePacketData && (!error || (error && *error == nil))) {
            return [self verifyData:literalDataPacket.literalRawData withSignature:signaturePacketData error:error];
        }
        return NO;
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
- (NSSet<PGPKey *> *)importKeysFromFile:(NSString *)path {
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return [NSSet<PGPKey *> set];
    }

    return [self importKeysFromData:[NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil]];
}

- (NSSet<PGPKey *> *)importKeysFromData:(NSData *)data {
    PGPAssertClass(data, NSData);

    let loadedKeys = [self keysFromData:data];
    return [self importKeys:loadedKeys];
}

- (NSSet<PGPKey *> *)importKeys:(NSSet<PGPKey *> *)keys {
    PGPAssertClass(keys, NSSet);

    for (PGPKey *key in keys) {
        self.keys = [self addOrUpdateCompoundKeyForKey:key.secretKey inContainer:self.keys];
        self.keys = [self addOrUpdateCompoundKeyForKey:key.publicKey inContainer:self.keys];
    }
    return self.keys;
}

- (BOOL)importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path {
    let fullPath = [path stringByExpandingTildeInPath];

    let loadedKeys = [self keysFromFile:fullPath];
    if (loadedKeys.count == 0) {
        return NO;
    }

    let foundKey = [[loadedKeys objectsPassingTest:^BOOL(PGPKey *key, BOOL *stop) {
        *stop = [key.publicKey.keyID.shortKeyString.uppercaseString isEqualToString:shortKeyStringIdentifier.uppercaseString] || [key.secretKey.keyID.shortKeyString.uppercaseString isEqualToString:shortKeyStringIdentifier.uppercaseString];
        return *stop;

    }] anyObject];

    if (!foundKey) {
        return NO;
    }

    self.keys = [self.keys setByAddingObject:foundKey];

    return YES;
}

- (NSSet<PGPKey *> *)keysFromFile:(NSString *)path {
    NSString *fullPath = [path stringByExpandingTildeInPath];

    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:&isDirectory] || isDirectory) {
        return [NSSet<PGPKey *> set];
    }

    NSError *error = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe | NSDataReadingUncached error:&error];
    if (!fileData || error) {
        return [NSSet<PGPKey *> set];
    }

    return [self keysFromData:fileData];
}

- (NSSet<PGPKey *> *)keysFromData:(NSData *)fileData {
    NSAssert(fileData.length > 0, @"Empty data");

    let binRingData = [self convertArmoredMessage2BinaryBlocksWhenNecessary:fileData];
    if (!binRingData || binRingData.count == 0) {
        PGPLogError(@"Invalid input data");
        return [NSSet<PGPKey *> set];
    }

    var keys = [[NSSet<PGPKey *> alloc] init];
    for (NSData *data in binRingData) {
        let readPartialKeys = [self readPartialKeysFromData:data];
        for (PGPPartialKey *key in readPartialKeys) {
            keys = [self addOrUpdateCompoundKeyForKey:key inContainer:keys];
        }
    }

    return keys;
}

#pragma mark - Private

- (NSArray<PGPPacket *> *)readPacketsFromData:(NSData *)keyringData {
    PGPAssertClass(keyringData, NSData);

    if (keyringData.length == 0) {
        return @[];
    }

    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger offset = 0;
    NSUInteger nextPacketOffset = 0;

    while (offset < keyringData.length) {
        let packet = [PGPPacketFactory packetWithData:keyringData offset:offset nextPacketOffset:&nextPacketOffset];
        [accumulatedPackets pgp_addObject:packet];

        // corrupted data. Move by one byte in hope we find some packet there, or EOF.
        if (nextPacketOffset == 0) {
            offset++;
        }
        offset += nextPacketOffset;
    }

    return accumulatedPackets;
}

// Add or update compound key. Returns updated set.
- (NSSet<PGPKey *> *)addOrUpdateCompoundKeyForKey:(nullable PGPPartialKey *)key inContainer:(NSSet<PGPKey *> *)compoundKeys {
    if (!key) {
        return compoundKeys;
    }

    NSMutableSet *updatedContainer = [NSMutableSet<PGPKey *> setWithSet:compoundKeys];

    let foundCompoundKey = [[compoundKeys objectsPassingTest:^BOOL(PGPKey *obj, BOOL *stop) {
        *stop = [obj.publicKey.keyID isEqual:key.keyID] || [obj.secretKey.keyID isEqual:key.keyID];
        return *stop;
    }] anyObject];

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

- (NSSet<PGPPartialKey *> *)readPartialKeysFromData:(NSData *)messageData {
    let keys = [NSMutableSet<PGPPartialKey *> set];
    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger position = 0;
    NSUInteger nextPacketPosition = 0;

    while (position < messageData.length) {
        let packet = [PGPPacketFactory packetWithData:messageData offset:position nextPacketOffset:&nextPacketPosition];
        if (!packet) {
            position += (nextPacketPosition > 0) ? nextPacketPosition : 1;
            continue;
        }

        if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
            let key = [[PGPPartialKey alloc] initWithPackets:accumulatedPackets];
            [keys addObject:key];
            [accumulatedPackets removeAllObjects];
        }

        [accumulatedPackets pgp_addObject:packet];
        position += nextPacketPosition;
    }

    if (accumulatedPackets.count > 1) {
        let key = [[PGPPartialKey alloc] initWithPackets:accumulatedPackets];
        [keys addObject:key];
        [accumulatedPackets removeAllObjects];
    }

    return keys;
}

- (NSArray<NSData *> *)convertArmoredMessage2BinaryBlocksWhenNecessary:(NSData *)binOrArmorData {
    NSData *binRingData = binOrArmorData;
    // detect if armored, check for strin -----BEGIN PGP
    if ([PGPArmor isArmoredData:binRingData]) {
        NSError *deadmorError = nil;
        NSString *armoredString = [[NSString alloc] initWithData:binRingData encoding:NSUTF8StringEncoding];

        // replace \n to \r\n
        // propably unecessary since armore code care about \r\n or \n as newline sentence
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
        armoredString = [armoredString stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"];

        NSMutableArray *extractedBlocks = [[NSMutableArray alloc] init];
        NSRegularExpression *regex = [[NSRegularExpression alloc] initWithPattern:@"(-----)(BEGIN|END)[ ](PGP)[A-Z ]*(-----)" options:NSRegularExpressionDotMatchesLineSeparators error:nil];
        __block NSInteger offset = 0;
        [regex enumerateMatchesInString:armoredString options:NSMatchingReportCompletion range:NSMakeRange(0, armoredString.length) usingBlock:^(NSTextCheckingResult *_Nullable result, __unused NSMatchingFlags flags, __unused BOOL *stop) {
            NSString *substring = [armoredString substringWithRange:result.range];
            if ([substring containsString:@"END"]) {
                NSInteger endIndex = result.range.location + result.range.length;
                [extractedBlocks addObject:[armoredString substringWithRange:NSMakeRange(offset, endIndex - offset)]];
            } else if ([substring containsString:@"BEGIN"]) {
                offset = result.range.location;
            }
        }];

        let extractedData = [[NSMutableArray<NSData *> alloc] init];
        for (NSString *extractedString in extractedBlocks) {
            binRingData = [PGPArmor readArmoredData:extractedString error:&deadmorError];
            if (deadmorError) {
                return @[];
            } else {
                [extractedData addObject:binRingData];
            }
        }

        return extractedData;
    }
    return @[binRingData];
}

@end

NS_ASSUME_NONNULL_END
