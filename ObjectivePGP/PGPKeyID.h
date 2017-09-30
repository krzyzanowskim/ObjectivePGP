//
//  PGPKeyID.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/PGPMacros.h>
#import <ObjectivePGP/PGPExportableProtocol.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPFingerprint;

/// The eight-octet Key ID
@interface PGPKeyID : NSObject <PGPExportable, NSCopying>

/// The eight-octet Key identifier
@property (readonly, copy, nonatomic) NSData *longKey;
@property (readonly, nonatomic) NSString *longKeyString;

/// The four-octet Key identifier
@property (readonly, nonatomic) NSData *shortKey;
@property (readonly, nonatomic) NSString *shortKeyString;

PGP_EMPTY_INIT_UNAVAILABLE

/// Initialize with eight-octet key identifier
- (instancetype)initWithLongKey:(NSData *)longKeyData NS_DESIGNATED_INITIALIZER;

/// Initialize with fingerprint
- (instancetype)initWithFingerprint:(PGPFingerprint *)fingerprint;

@end

NS_ASSUME_NONNULL_END
