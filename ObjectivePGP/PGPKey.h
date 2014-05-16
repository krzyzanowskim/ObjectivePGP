//
//  PGPTransferableKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPPacket.h"
#import "PGPKeyID.h"
#import "PGPSignaturePacket.h"

typedef NS_ENUM(NSUInteger, PGPKeyType) {
    PGPKeyUnknown = 0,
    PGPKeySecret  = 1,
    PGPKeyPublic  = 2
};

@interface PGPKey : NSObject

@property (assign, readonly) PGPKeyType type;
@property (strong, nonatomic) id <PGPPacket> primaryKeyPacket;
@property (assign, readonly) BOOL isEncrypted;
@property (strong, nonatomic) NSMutableArray *users;
@property (strong, nonatomic) NSMutableArray *subKeys;
@property (strong, nonatomic) NSMutableArray *directSignatures;
@property (strong, nonatomic) id <PGPPacket> revocationSignature;

- (instancetype) initWithPackets:(NSArray *)packets;

/**
 *  Decrypts all secret key and subkey packets
 *
 *  @param passphrase Password
 *  @param error      error
 *
 *  @return YES on success
 */
- (BOOL) decrypt:(NSString *)passphrase error:(NSError *__autoreleasing *)error;

@end
