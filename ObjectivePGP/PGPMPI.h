//
//  OpenPGPMPI.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/bn.h>

@interface PGPMPI : NSObject

@property (nonatomic) NSString *identifier;
@property (nonatomic, readonly) BIGNUM *bignumRef;
/**
 *  Total bytes, header + body
 */
@property (nonatomic, readonly) NSUInteger packetLength;

- (instancetype) initWithMPIData:(NSData *)mpiData atPosition:(NSUInteger)position;
- (instancetype) initWithData:(NSData *)dataToMPI;
- (NSData *) exportMPI;
- (NSData *) bodyData;

@end
