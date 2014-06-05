//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPSymmetricallyEncryptedDataPacket.h"

@implementation PGPSymmetricallyEncryptedDataPacket

- (PGPPacketTag)tag
{
    return PGPSymmetricallyEncryptedDataPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error
{
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // The content of an encrypted data packet is more OpenPGP packets
    // once decrypted, so recursively handle them

    // - Encrypted data, the output of the selected symmetric-key cipher
    // operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
    position = position + packetBody.length;
    return position;
}

- (NSData *)exportPacket:(NSError *__autoreleasing *)error
{
    NSMutableData *data = [NSMutableData data];
    NSData *bodyData = self.bodyData;
    NSData *headerData = [self buildHeaderData:bodyData];
    [data appendData: headerData];
    [data appendData: bodyData];
    return [data copy];
}

#pragma mark - Private

- (void) decrypt
{
    // decrypt packets
    // and parse decrypted packets readPacketsBinaryData (private in ObjectivePGP)
    //	return __ops_decrypt_se_data(OPS_PTAG_CT_SE_DATA_BODY, region, stream);
    
}

- (void) encrypt
{
    //TODO: encrypt decrypted packets
}

@end
