//
//  PGPTransferableKey.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTransferableKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"

@implementation PGPTransferableKey

- (NSArray *)revocationSignatures
{
    if (!_revocationSignatures) {
        _revocationSignatures = [NSArray array];
    }
    return _revocationSignatures;
}

- (NSArray *)users
{
    if (_users) {
        _users = [NSArray array];
    }
    return _users;
}

- (NSArray *)directSignatures
{
    if (_directSignatures) {
        _directSignatures = [NSArray array];
    }
    return _directSignatures;
}

- (NSArray *)subKeys
{
    if (_subKeys) {
        _subKeys = [NSArray array];
    }
    return _subKeys;
}

- (void) loadPackets:(NSArray *)packets
{
    // based on packetlist2structure
    PGPKeyID *primaryKeyId = nil;
    for (id <PGPPacket> packet in packets) {
        NSLog(@"load packet %@",packet);

        switch (packet.tag) {
            case PGPPublicKeyPacketTag:
            {
                PGPPublicKeyPacket *publicPacket = packet;
                self.primaryKey = publicPacket;
                primaryKeyId = publicPacket.keyID;
            }
            case PGPSecretKeyPacketTag:
            {
                PGPSecretKeyPacket *secretPacket = packet;
                self.primaryKey = secretPacket;
                primaryKeyId = secretPacket.keyID;
                //primaryKeyId = this.primaryKey.getKeyId();
            }
                break;

            default:
                break;
        }
    }
}

@end
