//
//  NSData+PBKDF2SHA1TripleDESEncryption.h
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/1/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

@import Foundation;


@interface NSString (PBKDF2SHA1TripleDESEncryption)

- (NSData *)encryptStringWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;

@end

@interface NSData (PBKDF2SHA1TripleDESEncryption)

- (NSData *)encryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;
- (NSData *)decryptWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;

- (NSString *)decryptStringWithKey:(NSData *)keyData initalizationVector:(NSData *)ivData useSignature:(BOOL)usesignature;


- (NSData *)encryptDataWithPassphrase:(NSString *)passPhrase salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
- (NSData *)decryptDataWithPassphrase:(NSString *)passPhrase salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;

- (NSData *)encryptDataWithPassword:(NSData *)passwordData salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;
- (NSData *)decryptDataWithPassword:(NSData *)passwordData salt:(NSData *)saltData pbkdf2Iterations:(NSNumber *)iterations initialisationVector:(NSData *)ivData;

@end
