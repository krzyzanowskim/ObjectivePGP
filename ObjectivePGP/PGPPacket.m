//
//  PGPPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//    4.1.  Overview
//
//    An OpenPGP message is constructed from a number of records that are
//    traditionally called packets.  A packet is a chunk of data that has a
//    tag specifying its meaning.  An OpenPGP message, keyring,
//    certificate, and so forth consists of a number of packets.  Some of
//    those packets may contain other OpenPGP packets (for example, a
//    compressed data packet, when uncompressed, contains OpenPGP packets).
//
//    Each packet consists of a packet header, followed by the packet body.
//    The packet header is of variable length.


#import "PGPPacket.h"

@interface PGPPacket ()
@end

@implementation PGPPacket

@end
