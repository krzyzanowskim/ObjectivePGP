//
//  NSInputStream+PGP.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSInputStream (PGP)
- (UInt8) readUInt8; // BE->LE
- (UInt8) readUInt8:(UInt8 *)bytes;
- (UInt8) readUInt8BytesAppendTo:(NSMutableData *)data;
- (UInt16) readUInt16; // BE->LE
- (UInt16) readUInt16:(UInt8 *)readBytes;
- (UInt16) readUInt16BytesAppendTo:(NSMutableData *)data;
- (UInt32) readUInt32; // BE->LE
- (UInt32) readUInt32:(UInt8 *)readBytes;
- (UInt32) readUInt32BytesAppendTo:(NSMutableData *)data;
- (NSData *) readDataLength:(NSUInteger)length;
@end
