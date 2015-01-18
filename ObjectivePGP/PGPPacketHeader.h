//
//  PGPHeader.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPPacketHeader : NSObject
@property (assign) BOOL isNew;
@property (assign) PGPPacketTag packetTag;
@property (assign) NSUInteger bodyLength;
@property (assign) BOOL bodyLengthIsPartial;

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;

@end
