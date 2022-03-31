//
//  NSData+RSAPublicKeyEncryption.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-10.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;


@interface NSData (RSAPublicKeyEncryption)

+ (NSArray *)newPrivatePublicKeyPairWithLength:(NSUInteger)length;
- (NSData *)encryptWithPublicKey:(NSData *)publicKeyData;
- (NSData *)decryptWithPrivateKey:(NSData *)privateKeyData;

- (NSData *)signatureWithPrivateKey:(NSData *)privateKeyData;
- (BOOL)verifyRSASignature:(NSData *)signatureData withPublicKey:(NSData *)publicKeyData;

// old methods

- (NSData *)	RSAencryptWithPublicKey:(NSString *)publicKeyString padding:(int)padding;
- (bool)		RSAcheckSignature:(NSData *)signature withPublicKey:(NSString *)publicKeyString type:(int)type;

@end
