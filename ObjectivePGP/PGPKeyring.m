//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPKeyring.h"

#import "PGPUser.h"
#import "PGPKey.h"
#import "PGPKey+Private.h"
#import "PGPPartialKey.h"
#import "PGPPartialSubKey.h"
#import "PGPArmor.h"

#import "PGPFoundation.h"
#import "PGPLogging.h"
#import "NSMutableData+PGPUtils.h"
#import "NSArray+PGPUtils.h"
#import "PGPMacros+Private.h"

#import <ObjectivePGP/ObjectivePGPObject.h>

@interface PGPKeyring ()

@property (strong, nonatomic, readwrite) NSArray<PGPKey *> *keys;

@end

@implementation PGPKeyring

- (instancetype)init {
    if ((self = [super init])) {
        _keys = [NSMutableArray<PGPKey *> array];
    }
    return self;
}

- (void)importKeys:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(keys, NSArray);

    for (PGPKey *key in keys) {
        self.keys = [self.class addOrUpdatePartialKey:key.secretKey inContainer:self.keys];
        self.keys = [self.class addOrUpdatePartialKey:key.publicKey inContainer:self.keys];
    }
}

- (BOOL)importKey:(NSString *)keyIdentifier fromPath:(NSString *)path error:(NSError * __autoreleasing _Nullable *)error {
    let fullPath = [path stringByExpandingTildeInPath];

    let loadedKeys = [self.class readKeysFromPath:fullPath error:error];
    if (loadedKeys.count == 0 || (error && *error)) {
        return NO;
    }

    let foundKey = [[loadedKeys pgp_objectsPassingTest:^BOOL(PGPKey *key, BOOL *stop) {
        *stop = PGPEqualObjects(key.publicKey.keyID.shortIdentifier.uppercaseString, keyIdentifier.uppercaseString) || PGPEqualObjects(key.secretKey.keyID.shortIdentifier.uppercaseString, keyIdentifier.uppercaseString) ||
        PGPEqualObjects(key.publicKey.keyID.longIdentifier.uppercaseString, keyIdentifier.uppercaseString) || PGPEqualObjects(key.secretKey.keyID.longIdentifier.uppercaseString, keyIdentifier.uppercaseString);
        return *stop;
    }] firstObject];

    if (!foundKey) {
        if (error) {
            *error = [NSError errorWithDomain:PGPErrorDomain code:PGPErrorNotFound userInfo:@{NSLocalizedDescriptionKey: @"Key not found."}];
        }
        return NO;
    }

    self.keys = [self.keys arrayByAddingObject:foundKey];

    return YES;
}

- (void)deleteKeys:(NSArray<PGPKey *> *)keys {
    PGPAssertClass(keys, NSArray);

    let allKeys = [NSMutableArray<PGPKey *> arrayWithArray:self.keys];
    for (PGPKey *key in keys) {
        [allKeys removeObject:key];
    }
    self.keys = allKeys;
}

- (void)deleteAll {
    [self deleteKeys:self.keys];
}

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
    return [self.class findKeyWithKeyID:searchKeyID in:self.keys];
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

- (BOOL)exportKeysOfType:(PGPKeyType)type toFile:(NSString *)path error:(NSError * __autoreleasing *)error {
    let exportKeys = [NSMutableArray<PGPPartialKey *> array];
    for (PGPKey *key in self.keys) {
        if (type == PGPKeyTypePublic && key.publicKey) {
            [exportKeys pgp_addObject:key.publicKey];
        }
        if (type == PGPKeyTypeSecret && key.secretKey) {
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
        if (![self.class appendKey:key toKeyring:path error:error]) {
            return NO;
        }
    }
    return YES;
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

+ (BOOL)appendKey:(PGPPartialKey *)key toKeyring:(NSString *)path error:(NSError * __autoreleasing *)error {
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
        let compoundKey = [[PGPKey alloc] initWithSecretKey:(key.type == PGPKeyTypeSecret ? key : nil) publicKey:(key.type == PGPKeyTypePublic ? key : nil)];
        [updatedContainer addObject:compoundKey];
    } else {
        if (key.type == PGPKeyTypePublic) {
            foundCompoundKey.publicKey = key;
        }
        if (key.type == PGPKeyTypeSecret) {
            foundCompoundKey.secretKey = key;
        }
    }

    return updatedContainer;
}

@end
