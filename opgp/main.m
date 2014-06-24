//
//  main.m
//  opgp
//
//  Created by Marcin Krzyzanowski on 24/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ObjectivePGP.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        fprintf(stdout, "%s\n", [@"ObjectivePGP v.0.1" UTF8String]);

        NSUserDefaults *standardDefaults = [NSUserDefaults standardUserDefaults];
        NSString *inputFile = [standardDefaults stringForKey:@"input"];
        NSString *outputFile = [standardDefaults stringForKey:@"output"];
        NSString *pubringFile = [standardDefaults stringForKey:@"pubring"];
        NSString *secringFile = [standardDefaults stringForKey:@"secring"];
        NSString *keyIdentifier = [standardDefaults stringForKey:@"key"];
        NSString *passprase = [standardDefaults stringForKey:@"passphrase"];
        BOOL armor = [standardDefaults boolForKey:@"armor"];

        if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-help"]) {
            fprintf(stdout, "Usage:\n");
            fprintf(stdout, "\t-decrypt     Decrypt mode (Default)\n");
            fprintf(stdout, "\t-encrypt     Encrypt mode \n");
            fprintf(stdout, "\t-input       file.txt - path to input file\n");
            fprintf(stdout, "\t-key         [28A83333F9C27197|F9C27197] - public or secret key identifier\n");
            fprintf(stdout, "\t-output      file.txt.gpg - output path (Optional)\n");
            fprintf(stdout, "\t-pubring     [pubring.gpg|pubring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-secring     [secring.gpg|secring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-passphrase  12345 - secret key password (Optional)\n");
            fprintf(stdout, "\t-armor       [1|0] - output format (Optional)\n");
            return 0;
        }
        
        BOOL encrypt = NO;
        if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-encrypt"]) {
            encrypt = YES;
        }
        
        if (!pubringFile) {
            pubringFile = [[NSHomeDirectory() stringByAppendingPathComponent:@".gnupg"] stringByAppendingPathComponent:@"pubring.gpg"];
        }
        if (!secringFile) {
            secringFile = [[NSHomeDirectory() stringByAppendingPathComponent:@".gnupg"] stringByAppendingPathComponent:@"secring.gpg"];
        }
        
        if (!outputFile) {
            outputFile = [inputFile stringByAppendingPathExtension:@"gpg"];
        }
        
        ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
        [pgp importKeysFromFile:[pubringFile stringByExpandingTildeInPath]];
        [pgp importKeysFromFile:[secringFile stringByExpandingTildeInPath]];

        PGPKey *operationKey = nil;
        operationKey = [pgp getKeyForIdentifier:keyIdentifier];
        if (!operationKey) {
            fprintf(stderr, "ERROR: Can't find key %s\n", keyIdentifier.UTF8String);
            return 1;
        }
        
        NSData *inputFileData = [NSData dataWithContentsOfMappedFile:[inputFile stringByExpandingTildeInPath]];
        
        NSData *outputData = nil;
        NSError *operationError = nil;
        if (encrypt) {
            outputData = [pgp encryptData:inputFileData usingPublicKey:operationKey armored:armor error:&operationError];
        } else {
            outputData = [pgp decryptData:inputFileData usingSecretKey:operationKey passphrase:passprase error:&operationError];
        }
        
        if (operationError) {
            fprintf(stderr, "ERROR: %s\n", operationError.localizedDescription.UTF8String);
        } else {
            if (![outputData writeToFile:[outputFile stringByExpandingTildeInPath] atomically:YES]) {
                fprintf(stderr, "Can't write to output file\n");
                return 1;
            }
        }
    }
    return 0;
}
