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

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/rsa.h>
#import <openssl/bn.h>

@implementation PGPPublicKeyRSA

// encrypts the bytes
+ (NSData *) publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket
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
    
    uint8_t *encrypted_em = calloc(BN_num_bytes(rsa->n) & SIZE_T_MAX, 1);
    int em_len = RSA_public_encrypt(toEncrypt.length & INT_MAX, toEncrypt.bytes, encrypted_em, rsa, RSA_NO_PADDING);
    
    if (em_len != publicKeyPacket.keySize) {
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
#ifdef DEBUG
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
#endif
        free(errBuf);

        free(encrypted_em);
        RSA_free(rsa);
        return nil;
    }
    
    // decrypted encoded EME
    NSData *encryptedEm = [NSData dataWithBytes:encrypted_em length:em_len];
    
    RSA_free(rsa);
    rsa->n = rsa->e = NULL;
    free(encrypted_em);
    
    return encryptedEm;
}

// decrypt bytes
+ (NSData *) privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket
{
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }
    
    rsa->n = BN_dup([[secretKeyPacket publicMPI:@"N"] bignumRef]);
    rsa->e = BN_dup([[secretKeyPacket publicMPI:@"E"] bignumRef]);
    
    rsa->d = BN_dup([[secretKeyPacket secretMPI:@"D"] bignumRef]);
    rsa->p = BN_dup([[secretKeyPacket secretMPI:@"Q"] bignumRef]);	/* p and q are round the other way in openssl */
    rsa->q = BN_dup([[secretKeyPacket secretMPI:@"P"] bignumRef]);
    
    if (rsa->d == NULL) {
        return nil;
    }
    
    if (RSA_check_key(rsa) != 1) {
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
#ifdef DEBUG
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
#endif
        free(errBuf);
        
        ERR_free_strings();
        return nil;
    }

    UInt8 *outbuf = calloc(RSA_size(rsa), 1);
    int t = RSA_private_decrypt(toDecrypt.length & INT_MAX , toDecrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t < 0) {
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
#ifdef DEBUG
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
#endif
        free(errBuf);
        
        ERR_free_strings();
        free(outbuf);
        return nil;
    }
    
    NSData *decryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(decryptedData, @"Missing data");
    
    
    free(outbuf);
    RSA_free(rsa);
    rsa->n = rsa->d = rsa->p = rsa->q = rsa->e = NULL;
    
    return decryptedData;
}

// sign
+ (NSData *) privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket
{
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nil;
    }

    rsa->n = BN_dup([[secretKeyPacket publicMPI:@"N"] bignumRef]);
    rsa->d = BN_dup([[secretKeyPacket secretMPI:@"D"] bignumRef]);
    rsa->p = BN_dup([[secretKeyPacket secretMPI:@"Q"] bignumRef]);	/* p and q are round the other way in openssl */
    rsa->q = BN_dup([[secretKeyPacket secretMPI:@"P"] bignumRef]);
    rsa->e = BN_dup([[secretKeyPacket publicMPI:@"E"] bignumRef]);

    if (toEncrypt.length > secretKeyPacket.keySize) {
        return nil;
    }


    /* If this isn't set, it's very likely that the programmer hasn't */
    /* decrypted the secret key. RSA_check_key segfaults in that case. */
    if (rsa->d == NULL) {
        return nil;
    }

    if (RSA_check_key(rsa) != 1) {
        ERR_load_crypto_strings();
        SSL_load_error_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        return nil;
    }


    UInt8 *outbuf = calloc(RSA_size(rsa), 1);
    int t = RSA_private_encrypt(toEncrypt.length & INT_MAX, (UInt8 *)toEncrypt.bytes, outbuf, rsa, RSA_NO_PADDING);
    if (t < 0) {
        ERR_load_crypto_strings();
        SSL_load_error_strings();

        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        ERR_free_strings();
        free(outbuf);
        return nil;
    }

    NSData *encryptedData = [NSData dataWithBytes:outbuf length:t];
    NSAssert(encryptedData, @"Missing calculated data");


    free(outbuf);
    RSA_free(rsa);
    rsa->n = rsa->d = rsa->p = rsa->q = rsa->e = NULL;

    return encryptedData;
}

// recovers the message digest
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

    UInt8 *decrypted_em = calloc(RSA_size(rsa) - 11, 1);
    int em_len = RSA_public_decrypt(toDecrypt.length & INT_MAX, toDecrypt.bytes, decrypted_em, rsa, RSA_NO_PADDING);

    if (em_len != publicKeyPacket.keySize) {
        free(decrypted_em);
        RSA_free(rsa);
        
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        ERR_error_string(err_code, errBuf);
        NSLog(@"%@",[NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        free(errBuf);

        return nil;
    }

    // decrypted PKCS emsa
    NSData *decryptedEm = [NSData dataWithBytes:decrypted_em length:em_len];

    RSA_free(rsa);
    rsa->n = rsa->e = NULL;
    free(decrypted_em);

    return decryptedEm;
}

@end
