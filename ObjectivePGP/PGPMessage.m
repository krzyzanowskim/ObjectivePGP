//
//  PGPMessage.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//
//    11.3.  OpenPGP Messages
//
//    An OpenPGP message is a packet or sequence of packets that
//    corresponds to the following grammatical rules (comma represents sequential composition,
//    and vertical bar separates alternatives):
//
//    OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
//
//    Compressed Message :- Compressed Data Packet.
//
//    Literal Message :- Literal Data Packet.
//
//    ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
//
//    ESK Sequence :- ESK | ESK Sequence, ESK.
//
//    Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
//
//    Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
//
//    One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
//
//    Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
//
//    In addition, decrypting a Symmetrically Encrypted Data packet or a
//    Symmetrically Encrypted Integrity Protected Data packet as well as
//    decompressing a Compressed Data packet must yield a valid OpenPGP
//    Message.
//

#import "PGPMessage.h"

@implementation PGPMessage

@end
