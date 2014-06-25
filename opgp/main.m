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
        NSString *inputPath = [standardDefaults stringForKey:@"input"];
        NSString *outputFile = [standardDefaults stringForKey:@"output"];
        NSString *pubringFile = [standardDefaults stringForKey:@"pubring"];
        NSString *secringFile = [standardDefaults stringForKey:@"secring"];
        NSString *keyIdentifier = [standardDefaults stringForKey:@"keyid"];
        NSString *keyFile = [standardDefaults stringForKey:@"key"];
        NSString *passprase = [standardDefaults stringForKey:@"passphrase"];
        BOOL armor = [standardDefaults boolForKey:@"armor"];
        
        if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-help"]) {
            fprintf(stdout, "Usage:\n");
            fprintf(stdout, "\t-decrypt     Decrypt mode (Default)\n");
            fprintf(stdout, "\t-encrypt     Encrypt mode \n");
            fprintf(stdout, "\t-input       file.txt - path or URL to input file\n");
            fprintf(stdout, "\t-keyid       [28A83333F9C27197|F9C27197] - public or secret key identifier (Optional if \"-key\" is specified)\n");
            fprintf(stdout, "\t-key         key.asc - public or secret key file\n");
            fprintf(stdout, "\t-output      file.txt.gpg - output path (Optional)\n");
            fprintf(stdout, "\t-pubring     [pubring.gpg|pubring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-secring     [secring.gpg|secring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-passphrase  12345 - secret key password (Optional)\n");
            fprintf(stdout, "\t-armor       [1|0] - output format (Optional)\n");
            fprintf(stdout, "\t-help        Help\n");
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
        
        // load or fetch input file
        NSData *inputFileData = nil;
        NSURL *inputURL = [NSURL URLWithString:inputPath];
        if (inputURL.scheme) {
            NSError *loadURLError = nil;
            inputFileData = [NSData dataWithContentsOfURL:inputURL options:NSDataReadingMappedIfSafe error:&loadURLError];
            if (loadURLError) {
                fprintf(stderr, "ERROR: Unable to fetch %s\n", inputPath.UTF8String);
                return 1;
            }
        } else {
            inputFileData = [NSData dataWithContentsOfMappedFile:inputPath];
        }
        
        if (!inputFileData) {
            fprintf(stderr, "ERROR: Invalid input data\n");
            return 1;
        }

        // Build output filename
        if (!outputFile) {
            outputFile = [[inputPath lastPathComponent] stringByAppendingPathExtension:@"gpg"];
        }
        
        ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
        
        if (pubringFile) {
            [pgp importKeysFromFile:[pubringFile stringByExpandingTildeInPath]];
        }
        
        if (secringFile) {
            [pgp importKeysFromFile:[secringFile stringByExpandingTildeInPath]];
        }
        
        PGPKey *operationKey = nil;
        if (keyFile) {
            NSData *fetchedKeyData = nil;
            NSURL *keyURL = [NSURL URLWithString:keyFile];
            if (keyURL.scheme) {
                NSError *loadURLError = nil;
                fetchedKeyData = [NSData dataWithContentsOfURL:keyURL options:NSDataReadingMappedIfSafe error:&loadURLError];
                if (loadURLError) {
                    fprintf(stderr, "ERROR: Unable to fetch key at %s\n", keyFile.UTF8String);
                    return 1;
                }
            } else {
                fetchedKeyData = [NSData dataWithContentsOfMappedFile:[keyFile stringByExpandingTildeInPath]];
            }

            NSArray *loadedKeys = [pgp importKeysFromData:fetchedKeyData];
            if (!keyIdentifier) {
                PGPKey *key = [loadedKeys firstObject];
                operationKey = key;
            }
        }

        if (keyIdentifier) {
            operationKey = [pgp getKeyForIdentifier:keyIdentifier];
            if (!operationKey) {
                fprintf(stderr, "ERROR: Can't use key %s\n", keyIdentifier.UTF8String);
                return 1;
            }
        }
        
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
                fprintf(stderr, "ERROR: Can't write to output file\n");
                return 1;
            }
        }
    }
    return 0;
}
