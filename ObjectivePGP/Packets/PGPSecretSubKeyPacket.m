//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//  A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
//  Key packet and has exactly the same format.

#import "PGPSecretSubKeyPacket.h"

@implementation PGPSecretSubKeyPacket

- (PGPPacketTag)tag {
    return PGPSecretSubkeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    return [super parsePacketBody:packetBody error:error];
}

@end
