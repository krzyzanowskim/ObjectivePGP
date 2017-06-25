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
#import "PGPCompoundKey.h"
#import "PGPCompoundKey+Private.h"
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

#import "PGPFoundation.h"
#import "PGPMacros.h"
#import "PGPLogging.h"


NS_ASSUME_NONNULL_BEGIN

@interface ObjectivePGP ()

@property (strong, nonatomic, readwrite) NSSet<PGPCompoundKey *> *keys;

@end

@implementation ObjectivePGP

- (instancetype)init {
    if ((self = [super init])) {
        _keys = [NSMutableSet<PGPCompoundKey *> set];
    }
    return self;
}

#pragma mark - Search

- (NSArray<PGPCompoundKey *> *)findKeysForUserID:(nonnull NSString *)userID {
    return [[self.keys objectsPassingTest:^BOOL(PGPCompoundKey *key, BOOL *stop1) {
        let a = key.publicKey ? [key.publicKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, NSUInteger idx, BOOL *stop2) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        let b = key.secretKey ? [key.secretKey.users indexOfObjectPassingTest:^BOOL(PGPUser *user, NSUInteger idx, BOOL *stop3) {
            return [userID isEqual:user.userID];
        }] : NSNotFound;

        return (a != NSNotFound) || (b != NSNotFound);
    }] allObjects];
}

- (nullable PGPCompoundKey *)findKeyForKeyID:(PGPKeyID *)searchKeyID {
    PGPAssertClass(searchKeyID, PGPKeyID);

    return [[self.keys objectsPassingTest:^BOOL(PGPCompoundKey *key, BOOL *stop) {
        // top-level keys
        __block BOOL found = (key.publicKey && [key.publicKey.keyID isEqual:searchKeyID]);
        if (!found) {
            found = (key.secretKey && [key.secretKey.keyID isEqual:searchKeyID]);
        }

        // subkeys
        if (!found && key.publicKey.subKeys.count > 0) {
            found = [key.publicKey.subKeys indexOfObjectPassingTest:^BOOL(PGPSubKey *subkey, NSUInteger idx, BOOL *stop2) {
                let subFound = [subkey.keyID isEqual:searchKeyID];
                *stop2 = subFound;
                return subFound;
            }] != NSNotFound;
        }

        if (!found && key.secretKey.subKeys.count > 0) {
            found = [key.secretKey.subKeys indexOfObjectPassingTest:^BOOL(PGPSubKey *subkey, NSUInteger idx, BOOL *stop2) {
                let subFound = [subkey.keyID isEqual:searchKeyID];
                *stop2 = subFound;
                return subFound;
            }] != NSNotFound;
        }

        *stop = found;
        return found;
    }] anyObject];
}

//TODO: rename to getKeyForFingerprint or something
- (nullable PGPCompoundKey *)findKeyForIdentifier:(NSString *)keyIdentifier {
    PGPAssertClass(keyIdentifier, NSString);

    if (keyIdentifier.length != 8 && keyIdentifier.length != 16) {
        PGPLogDebug(@"Invalid key identifier: %@", keyIdentifier);
        return nil;
    }

    BOOL useShortIdentifier = keyIdentifier.length == 8;

    // public
    for (PGPCompoundKey *key in self.keys) {
        if (key.publicKey) {
            let identifier = useShortIdentifier ? key.publicKey.keyID.shortKeyString : key.publicKey.keyID.longKeyString;
            if ([identifier.uppercaseString isEqual:keyIdentifier.uppercaseString]) {
                return key;
            }

            for (PGPSubKey *subkey in key.publicKey.subKeys) {
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

            for (PGPSubKey *subkey in key.secretKey.subKeys) {
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

- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing *)error {
    let exportKeys = [NSMutableArray<PGPKey *> array];
    for (PGPCompoundKey *key in self.keys) {
        if (type == PGPKeyPublic && key.publicKey) {
            [exportKeys addObject:key.publicKey];
        }
        if (type == PGPKeySecret && key.secretKey) {
            [exportKeys addObject:key.secretKey];
        }
    }
    return [self exportKeys:exportKeys toFile:path error:error];
}

- (BOOL)exportKeys:(NSArray<PGPKey *> *)keys toFile:(NSString *)path error:(NSError * __autoreleasing *)error {
    NSParameterAssert(keys);
    PGPAssertClass(path, NSString);

    if (keys.count == 0) {
        return NO;
    }

    for (PGPKey *key in keys) {
        if (![self appendKey:key toKeyring:path error:error]) {
            return NO;
        }
    }
    return YES;
}


- (BOOL) appendKey:(PGPKey *)key toKeyring:(NSString *)path error:(NSError * __autoreleasing *)error
{
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

- (nullable NSData *)exportKey:(PGPCompoundKey *)key armored:(BOOL)armored {
    PGPAssertClass(key, PGPCompoundKey);

    NSError *exportError = nil;
    NSData *keyData = [key export:&exportError];
    if (!keyData || exportError) {
        PGPLogDebug(@"%@",exportError);
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

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase error:(NSError * __autoreleasing *)error {
    return [self decryptData:messageDataToDecrypt passphrase:passphrase verifyWithKey:nil signed:nil valid:nil integrityProtected:nil error:error];
}

- (nullable NSData *)decryptData:(NSData *)messageDataToDecrypt passphrase:(nullable NSString *)passphrase verifyWithKey:(nullable PGPCompoundKey *)key signed:(nullable BOOL *)isSigned valid:(nullable BOOL *)isValid integrityProtected:(nullable BOOL *)isIntegrityProtected error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(messageDataToDecrypt, NSData);
    let binaryMessages = [self convertArmoredMessage2BinaryBlocksWhenNecessary:messageDataToDecrypt];

    //decrypt first message only
    let binaryMessageToDecrypt = binaryMessages.count > 0 ? binaryMessages.firstObject : nil;
    if (!binaryMessageToDecrypt) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Invalid input data"}];
        }
        return nil;
    }
    
    // parse packets
    var packets = [self readPacketsFromData:binaryMessageToDecrypt];
    
    PGPSymmetricAlgorithm sessionKeyAlgorithm = 0;
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
            if (decryptionSecretKeyPacket.isEncryptedWithPassword) {
                if (!passphrase) {
                    if (error) {
                        *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorPassphraseRequired userInfo:@{NSLocalizedDescriptionKey: @"Password is required for key"}];
                    }
                    return nil;
                }
                
                decryptionSecretKeyPacket = [decryptionSecretKeyPacket decryptedKeyPacket:passphrase error:error];
                if (!decryptionSecretKeyPacket || (error && *error)) {
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
    NSData *plaintextData;
    for (PGPPacket *packet in packets) {
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
                signaturePacket = PGPCast(packet,PGPSignaturePacket);
                break;
            default:
                if (error) {
                    *error = [NSError errorWithDomain:PGPErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unknown packet (expected literal or compressed)"}];
                }
                return nil;
        }
    }
    
    BOOL _signed = signaturePacket != nil;
    BOOL _valid = NO;
    if (signaturePacket && key.publicKey) {
        _valid = [self verifyData:plaintextData withSignature:signaturePacket.packetData usingKey:key error:nil];
    }

    if (isSigned) {
        *isSigned = _signed;
    } if (isValid) {
        *isValid = _valid;
    }

    return plaintextData;
}

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error; {
    return [self encryptData:dataToEncrypt usingKeys:keys signWithKey:nil passphrase:nil armored:armored error:error];
}

- (nullable NSData *)encryptData:(NSData *)dataToEncrypt usingKeys:(NSArray<PGPCompoundKey *> *)keys signWithKey:(nullable PGPCompoundKey *)signKey passphrase:(nullable NSString *)passphrase armored:(BOOL)armored error:(NSError * __autoreleasing _Nullable *)error {
    let publicKeys = [NSMutableArray<PGPKey *> array];
    for (PGPCompoundKey *key in keys) {
        [publicKeys addObject:key.publicKey];
    }

    let encryptedMessage = [NSMutableData data];
    
    //PGPPublicKeyEncryptedSessionKeyPacket goes here
    let preferredSymmeticAlgorithm = [PGPKey preferredSymmetricAlgorithmForKeys:publicKeys];
    
    // Random bytes as a string to be used as a key
    NSUInteger keySize = [PGPCryptoUtils keySizeOfSymmetricAlgorithm:preferredSymmeticAlgorithm];
    uint8_t buf[keySize];
    if (SecRandomCopyBytes(kSecRandomDefault, keySize, buf) == -1) {
        return nil;
    }

    let sessionKeyData = [NSMutableData dataWithBytes:buf length:keySize];
    
    for (PGPKey *publicKey in publicKeys) {
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
        if (*error) {
            return nil;
        }
        [encryptedMessage appendData:[eskKeyPacket export:error]];
        if (*error) {
            return nil;
        }
    }

    NSData *content;
    // sign data if requested
    if (signKey) {
        content = [self signData:dataToEncrypt usingKey:signKey passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:NO error:error];
        if (*error) {
            return nil;
        }
        
    } else {
        // Prepare literal packet
        let literalPacket = [PGPLiteralPacket literalPacket:PGPLiteralPacketBinary withData:dataToEncrypt];
        literalPacket.filename = nil;
        literalPacket.timestamp = [NSDate date];
        PGPLogWarning(@"Missing literal data");
        if (*error) {
            return nil;
        }
        let literalPacketData = [literalPacket export:error];
        if (*error) {
            return nil;
        }
        
        let compressedPacket = [[PGPCompressedPacket alloc] initWithData:literalPacketData type:PGPCompressionBZIP2];
        content = [compressedPacket export:error];
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

    [encryptedMessage appendData:[symEncryptedDataPacket export:error]];
    if (*error) {
        return nil;
    }

    if (armored) {
        return [PGPArmor armoredData:encryptedMessage as:PGPArmorTypeMessage];
    }

    return [encryptedMessage copy];
}

#pragma mark - Sign & Verify

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase detached:(BOOL)detached error:(NSError * __autoreleasing *)error {
    //TODO: configurable defaults for prefered hash
    return [self signData:dataToSign usingKey:key passphrase:passphrase hashAlgorithm:PGPHashSHA512 detached:detached error:error];
}

- (nullable NSData *)signData:(NSData *)dataToSign usingKey:(PGPCompoundKey *)key passphrase:(nullable NSString *)passphrase hashAlgorithm:(PGPHashAlgorithm)preferedHashAlgorithm detached:(BOOL)detached error:(NSError * __autoreleasing *)error {
    PGPAssertClass(dataToSign, NSData);
    PGPAssertClass(key, PGPCompoundKey);

    let signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument hashAlgorithm:preferedHashAlgorithm];
    if (![signaturePacket signData:dataToSign usingKey:key passphrase:passphrase userID:nil error:error]) {
        PGPLogDebug(@"Can't sign data");
        return nil;
    }

    NSError *exportError = nil;
    NSData *signaturePacketData = [signaturePacket export:&exportError];
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
        [signedMessage appendData:[onePassPacket export:&onePassExportError]];
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
        [signedMessage appendData:[literalPacket export:&literalExportError]];
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

- (BOOL)verifyData:(NSData *)signedData withSignature:(NSData *)signatureData error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(signatureData, NSData);

    // search for key in keys
    let packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        PGPLogWarning(@"Missing key signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing signature packet"}];
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
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing issuer"}];
        }
        return NO;
    }

    return [self verifyData:signedData withSignature:signatureData usingKey:issuerKey error:error];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPCompoundKey *)key error:(NSError * __autoreleasing _Nullable *)error {
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(signedData, NSData);
    PGPAssertClass(key, PGPCompoundKey);

    let packet = [PGPPacketFactory packetWithData:signatureData offset:0 nextPacketOffset:NULL];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        NSAssert(false, @"need signature");
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorGeneral userInfo:@{NSLocalizedDescriptionKey: @"Missing signature"}];
        }
        return NO;
    }

    let signaturePacket = PGPCast(packet, PGPSignaturePacket);
    if (!signaturePacket) {
        return NO;
    }
    BOOL verified = [signaturePacket verifyData:signedData withKey:key.publicKey userID:nil error:error];

    return verified;
}

- (BOOL) verifyData:(NSData *)signedDataPackets error:(NSError * __autoreleasing *)error
{
    // this is propably not the best solution when it comes to memory consumption
    // because literal data is copied more than once (first at parse phase, then when is come to build signature packet data
    // I belive this is unecessary but require more work. Schedule to v2.0
    @autoreleasepool {
        // search for signature packet
        let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
        NSUInteger offset = 0;
        NSUInteger nextPacketOffset;
        //TODO: dont parse data here, get raw data and pass to verifyData:withsignature:
        while (offset < signedDataPackets.length) {
            let packet = [PGPPacketFactory packetWithData:signedDataPackets offset:offset nextPacketOffset:&nextPacketOffset];
            if (packet) {
                [accumulatedPackets addObject:packet];
            }

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
- (NSSet<PGPCompoundKey *> *)importKeysFromFile:(NSString *)path {
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return [NSSet<PGPCompoundKey *> set];
    }
    
    return [self importKeysFromData:[NSData dataWithContentsOfFile:path]];
}

- (NSSet<PGPCompoundKey *> *)importKeysFromData:(NSData *)data {
    let loadedKeys = [self keysFromData:data];
    for (PGPCompoundKey *key in loadedKeys) {
        self.keys = [self addOrUpdateCompoundKeyForKey:key.secretKey inContainer:self.keys];
        self.keys = [self addOrUpdateCompoundKeyForKey:key.publicKey inContainer:self.keys];
    }
    return loadedKeys;
}

- (BOOL)importKey:(NSString *)shortKeyStringIdentifier fromFile:(NSString *)path {
    let fullPath = [path stringByExpandingTildeInPath];

    let loadedKeys = [self keysFromFile:fullPath];
    if (loadedKeys.count == 0) {
        return NO;
    }

    let foundKey = [[loadedKeys objectsPassingTest:^BOOL(PGPCompoundKey *key, BOOL *stop) {
        let condition = [key.publicKey.keyID.shortKeyString.uppercaseString isEqualToString:shortKeyStringIdentifier.uppercaseString] ||
                        [key.secretKey.keyID.shortKeyString.uppercaseString isEqualToString:shortKeyStringIdentifier.uppercaseString];

        if (condition) {
            *stop = YES;
        }
        return condition;

    }] anyObject];

    if (!foundKey) {
        return NO;
    }

    self.keys = [self.keys setByAddingObject:foundKey];

    return YES;
}

- (NSSet<PGPCompoundKey *> *)keysFromFile:(NSString *)path {
    NSString *fullPath = [path stringByExpandingTildeInPath];
    
    BOOL isDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:&isDirectory] || isDirectory) {
        return [NSSet<PGPCompoundKey *> set];
    }

    NSError *error = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:fullPath options:NSDataReadingMappedIfSafe | NSDataReadingUncached error:&error];
    if (!fileData || error) {
        return [NSSet<PGPCompoundKey *> set];
    }
    
    return [self keysFromData:fileData];
}

- (NSSet<PGPCompoundKey *> *)keysFromData:(NSData *)fileData {
    NSAssert(fileData.length > 0, @"Empty data");

    let binRingData = [self convertArmoredMessage2BinaryBlocksWhenNecessary:fileData];
    if (!binRingData || binRingData.count == 0) {
        PGPLogError(@"Invalid input data");
        return [NSSet<PGPCompoundKey *> set];
    }

    var keys = [[NSSet<PGPCompoundKey *> alloc] init];
    for (NSData *data in binRingData) {
        let readPartialKeys = [self readPartialKeysFromData:data];
        for (PGPKey *key in readPartialKeys) {
            keys = [self addOrUpdateCompoundKeyForKey:key inContainer:keys];
        }
    }

    return keys;
}

#pragma mark - Private

- (NSArray<PGPPacket *> *)readPacketsFromData:(NSData *)keyringData {
    PGPAssertClass(keyringData, NSData);

    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger offset = 0;
    NSUInteger nextPacketOffset = 0;
    
    while (offset < keyringData.length) {
        let packet = [PGPPacketFactory packetWithData:keyringData offset:offset nextPacketOffset:&nextPacketOffset];
        if (packet) {
            [accumulatedPackets addObject:packet];
        }
        
        offset += nextPacketOffset;
    }
    
    return accumulatedPackets;
}

// Add or update compound key. Returns updated set.
- (NSSet<PGPCompoundKey *> *)addOrUpdateCompoundKeyForKey:(nullable PGPKey *)key inContainer:(NSSet<PGPCompoundKey *> *)compoundKeys {
    if (!key) {
        return compoundKeys;
    }

    NSMutableSet *updatedContainer = [NSMutableSet<PGPCompoundKey *> setWithSet:compoundKeys];
    
    let foundCompoundKey = [[compoundKeys objectsPassingTest:^BOOL(PGPCompoundKey *obj, BOOL *stop) {
        return [obj.publicKey.keyID isEqual:key.keyID] || [obj.secretKey.keyID isEqual:key.keyID];
    }] anyObject];

    if (!foundCompoundKey) {
        let compoundKey = [[PGPCompoundKey alloc] initWithSecretKey:(key.type == PGPKeySecret ? key : nil) publicKey:(key.type == PGPKeyPublic ? key : nil)];
        [updatedContainer addObject:compoundKey];
    } else {
        if (key.type == PGPKeyPublic) {
            foundCompoundKey.publicKey = key;
        }
        if (key.type == PGPKeySecret) {
            foundCompoundKey.secretKey = key;
        }
    }

    return updatedContainer;
}

- (NSSet<PGPKey *> *)readPartialKeysFromData:(NSData *)messageData {
    let keys = [NSMutableSet<PGPKey *> set];
    let accumulatedPackets = [NSMutableArray<PGPPacket *> array];
    NSUInteger position = 0;
    NSUInteger nextPacketPosition = 0;

    while (position < messageData.length) {
        let packet = [PGPPacketFactory packetWithData:messageData offset:position nextPacketOffset:&nextPacketPosition];
        if (!packet) {
            position += nextPacketPosition;
            continue;
        }

        if ((accumulatedPackets.count > 1) && ((packet.tag == PGPPublicKeyPacketTag) || (packet.tag == PGPSecretKeyPacketTag))) {
            let key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
            [keys addObject:key];
            [accumulatedPackets removeAllObjects];
        }

        [accumulatedPackets addObject:packet];
        position += nextPacketPosition;
    }

    if (accumulatedPackets.count > 1) {
        PGPKey *key = [[PGPKey alloc] initWithPackets:accumulatedPackets];
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
        [regex enumerateMatchesInString:armoredString options:0 range:NSMakeRange(0, armoredString.length) usingBlock:^(NSTextCheckingResult * _Nullable result, NSMatchingFlags flags, BOOL *stop) {
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

