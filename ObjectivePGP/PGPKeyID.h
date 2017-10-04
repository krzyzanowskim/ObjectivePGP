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
NS_SWIFT_NAME(KeyID) @interface PGPKeyID : NSObject <PGPExportable, NSCopying>

/// The eight-octet Key identifier
@property (readonly, nonatomic) NSString *longIdentifier;

/// The four-octet Key identifier
@property (readonly, nonatomic) NSString *shortIdentifier;

PGP_EMPTY_INIT_UNAVAILABLE

/// Initialize with eight-octet key identifier
- (nullable instancetype)initWithLongKey:(NSData *)data NS_DESIGNATED_INITIALIZER;

/// Initialize with fingerprint
- (instancetype)initWithFingerprint:(PGPFingerprint *)fingerprint;

@end

NS_ASSUME_NONNULL_END
