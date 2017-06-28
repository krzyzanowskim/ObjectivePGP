//
//  OpenPGPMPI.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPBigNum.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPMPI : NSObject

@property (nonatomic, readonly, nullable) NSString *identifier;
@property (nonatomic, readonly) PGPBigNum *bigNum;
/**
 *  Total bytes, header + body
 */
@property (nonatomic, readonly) NSUInteger packetLength;

- (instancetype)initWithMPIData:(NSData *)mpiData identifier:(nullable NSString *)identifier atPosition:(NSUInteger)position;
- (instancetype)initWithData:(NSData *)dataToMPI;
- (nullable NSData *)exportMPI;
- (nullable NSData *)bodyData;

@end

NS_ASSUME_NONNULL_END
