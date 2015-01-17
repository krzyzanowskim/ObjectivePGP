//
//  PGPPacketHeader.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, PGPHeaderPacketTag) {
    PGPHeaderPacketTagNewFormat  = 0x40,
    PGPHeaderPacketTagAllwaysSet = 0x80
};



@protocol PGPPacketHeader <NSObject>
@end

@interface PGPPacketHeader : NSObject
@property (assign, readonly) NSInteger packetTag;
@property (assign, readonly) UInt8 headerLength;
@property (assign, readonly) UInt32 bodyLength;

@property (assign, readonly, getter=isBodyLengthPartial) BOOL bodyLengthPartial;
@end
