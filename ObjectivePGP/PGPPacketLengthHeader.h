//
//  PGPHeaderLength.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPPacketLengthHeader : NSObject
@property (assign) NSUInteger bodyLength;
@property (assign, getter=isPartial) BOOL partial;

- (BOOL) readNewFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
- (BOOL) readOldFromStream:(NSInputStream *)inputStream lengthType:(UInt8)lengthType error:(NSError * __autoreleasing *)error;

@end
