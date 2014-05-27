//
//  PGPPublicKeyAlgorithmRSA.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicKeyRSA.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPKey.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"

#import <openssl/rsa.h>
#import <openssl/bn.h>

@implementation PGPPublicKeyRSA

+ (NSData *) privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket
{
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }

    ;
    rsa->n = BN_dup([[secretKeyPacket publicMPI:@"N"] bignumRef]);
    rsa->d = BN_dup([[secretKeyPacket secretMPI:@"D"] bignumRef]);
    rsa->p = BN_dup([[secretKeyPacket secretMPI:@"Q"] bignumRef]);	/* p and q are round the other way in openssl */
    rsa->q = BN_dup([[secretKeyPacket secretMPI:@"P"] bignumRef]);
    rsa->e = BN_dup([[secretKeyPacket publicMPI:@"E"] bignumRef]);

    int keysize = (BN_num_bits(rsa->n) + 7) / 8;

    if (toEncrypt.length > keysize) {
        return nil;
    }

    // With RSA signatures, the hash value is encoded using PKCS#1 1.5
    // toHashData = [@"Plaintext\n" dataUsingEncoding:NSUTF8StringEncoding];
    // NSData *em = [PGPPKCSEmsa encode:self.hashAlgoritm m:toHashData emLen:keysize error:nil];

    /* If this isn't set, it's very likely that the programmer hasn't */
    /* decrypted the secret key. RSA_check_key segfaults in that case. */
    /* Use __ops_decrypt_seckey() to do that. */
    if (rsa->d == NULL) {
        return nil;
    }

    if (RSA_check_key(rsa) != 1) {
//        ERR_load_crypto_strings();
//        SSL_load_error_strings();
//
//        unsigned long err_code = ERR_get_error();
//        char *errBuf = calloc(512, sizeof(UInt8));
//        ERR_error_string(err_code, errBuf);
//        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
//        free(errBuf);
//
//        ERR_free_strings();
        return nil;
    }


    UInt8 *outbuf = calloc(RSA_size(rsa), sizeof(UInt8));
    int t = RSA_private_encrypt(keysize, (UInt8 *)toEncrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t < 0) {
//        ERR_load_crypto_strings();
//        SSL_load_error_strings();
//
//        unsigned long err_code = ERR_get_error();
//        char *errBuf = calloc(512, sizeof(UInt8));
//        ERR_error_string(err_code, errBuf);
//        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
//        free(errBuf);
//
//        ERR_free_strings();
        return nil;
    }

    NSData *encryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(encryptedData, @"Missing calculated data");


    free(outbuf);
    RSA_free(rsa);
    rsa->n = rsa->d = rsa->p = rsa->q = NULL;

    // build RSA result mpi
    //PGPMPI *mpi = [[PGPMPI alloc] initWithData:calculatedData];
    //[resultMPIs addObject:mpi];

    return encryptedData;
}

+ (NSData *) publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket
{
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }

    rsa->n = BN_dup([[publicKeyPacket publicMPI:@"N"] bignumRef]);
    rsa->e = BN_dup([[publicKeyPacket publicMPI:@"E"] bignumRef]);

    NSAssert(rsa->n && rsa->e, @"Missing N or E");
    if (!rsa->n || !rsa->e) {
        return nil;
    }

    uint8_t *decrypted_em = calloc(RSA_size(rsa) - 11, sizeof(UInt8));
    int em_len = RSA_public_decrypt(toDecrypt.length, toDecrypt.bytes, decrypted_em, rsa, RSA_NO_PADDING);

    if (em_len != publicKeyPacket.keySize) {
        return nil;
    }

    // decrypted PKCS emsa
    NSData *decrypted = [NSData dataWithBytes:decrypted_em length:em_len];

    RSA_free(rsa);
    rsa->n = rsa->e = NULL;
    free(decrypted_em);

    return decrypted;
}

@end
