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
#import "PGPUser.h"

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

- (BOOL) saveKeys:(NSArray *)keys toKeyring:(NSString *)path error:(NSError **)error
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

#pragma mark - Operations

- (NSData *) signData:(NSData *)dataToSign usingSecretKey:(PGPKey *)secretKey
{
    NSData *signaturePacketData = nil;

    // Some defaults
    PGPHashAlgorithm preferedHashAlgorithm = PGPHashSHA1;

    PGPSignaturePacket *signaturePacket = [PGPSignaturePacket signaturePacket:PGPSignatureBinaryDocument
                                                                hashAlgorithm:preferedHashAlgorithm];

    [signaturePacket signData:dataToSign secretKey:secretKey];
    signaturePacketData = [signaturePacket exportPacket:nil];
    return signaturePacketData;
}

- (NSData *) signData:(NSData *)dataToSign withKeyForUserID:(NSString *)userID
{
    PGPKey *key = [[self getKeysForUserID:userID] lastObject];
    NSAssert(key, @"Key is missing");

    if (!key) {
        return nil;
    }

    return [self signData:dataToSign usingSecretKey:key];
}

- (BOOL) verifyData:(NSData *)signedData withSignature:(NSData *)signatureData usingKey:(PGPKey *)publicKey
{
    if (!publicKey || !signatureData || !signatureData) {
        return NO;
    }

    id packet = [PGPPacketFactory packetWithData:signatureData offset:0];
    if (![packet isKindOfClass:[PGPSignaturePacket class]]) {
        return NO;
    }

    PGPSignaturePacket *signaturePacket = packet;
    BOOL verified = [signaturePacket verifyData:signedData withKey:publicKey userID:nil];

    return verified;
}

#pragma mark - Parse keyring

/**
 *  Load keyring file (secring or pubring)
 *
 *  @param path Path to file
 *
 *  @return YES on success
 */
- (BOOL) loadKeysFromKeyring:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:NO]) {
        return NO;
    }

    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
    if (!ringData) {
        return NO;
    }

    NSArray *parsedKeys = [self parseKeyring:ringData];
    if (parsedKeys.count == 0) {
        return NO;
    }

    self.keys = [self.keys arrayByAddingObjectsFromArray:parsedKeys];

    return YES;
}

- (BOOL) loadKey:(NSString *)shortKeyStringIdentifier fromKeyring:(NSString *)path
{
    NSString *fullPath = [path stringByExpandingTildeInPath];

    NSData *ringData = [NSData dataWithContentsOfFile:fullPath];
    if (!ringData) {
        return NO;
    }

    NSArray *parsedKeys = [self parseKeyring:ringData];
    if (parsedKeys.count == 0) {
        return NO;
    }

    __block BOOL foundKey = NO;
    [parsedKeys enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
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

/**
 *  Parse keyring data
 *
 *  @param keyringData Keyring data
 *
 *  @return Array of PGPKey
 */
- (NSArray *) parseKeyring:(NSData *)keyringData
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

@end
