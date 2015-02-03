//
//  PGPHeader.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPCommon.h"

@interface PGPPacketHeader : NSObject <NSCopying>
@property (assign) BOOL isNew;
@property (assign) PGPPacketTag packetTag;
@property (assign) UInt32 bodyLength;
@property (assign, getter=isPartial) BOOL partial;

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error;

@end
