//
//  JNXPasswordProtectedRSA.h
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/22/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

@import Foundation;

#import "JNXPasswordProtectedData.h"

@interface JNXPasswordProtectedRSA : NSObject <NSCoding>

@property (nonatomic,readonly)		NSData						*publicKey;
@property (nonatomic,readonly)		JNXPasswordProtectedData	*privateKey;

#
#pragma mark Initalisation
#
+ newWithPassword:(NSData *)passwordData;
- initWithPassword:(NSData *)passwordData;

+ newWithPublicKey:(NSData *)publicKey privateKey:(JNXPasswordProtectedData *)privateKey;
- initWithPublicKey:(NSData *)publicKey privateKey:(JNXPasswordProtectedData *)privateKey;
#
#pragma mark PublicKeyEncryption
#
- (NSData *)encryptData:(NSData *)dataToEncrypt;
- (NSData *)decryptData:(NSData *)dataToDecrypt password:(NSData *)passwordData;
- (NSData *)signData:(NSData *)dataToSign password:(NSData *)passwordData;
#
#pragma mark Password Caching
#
- (BOOL)hasCachedPassword;
- (void)deleteCachedPassword;
- (BOOL)cachePassword:(NSData *)passwordData;
#
#pragma mark Password Caching PublicKeyEncryption
#
- (NSData *)decryptData:(NSData *)dataToDecrypt;
- (NSData *)signData:(NSData *)dataToSign;


@end
