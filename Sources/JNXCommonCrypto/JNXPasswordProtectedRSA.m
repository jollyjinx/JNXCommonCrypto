//
//  JNXPasswordProtectedRSA.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/22/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//
#import "JNXPasswordProtectedRSA.h"
#import "JNXPasswordProtectedData.h"
#import "JNXCommonCrypto.h"

//@import JNXFree;
#import "JNXLog.h"

NSString *kS_privateKey = @"d";
NSString *kS_publicKey	= @"e";




@implementation JNXPasswordProtectedRSA
{
	JNXPasswordProtectedData 	*_privateKey;
	NSData						*_privateKeyDataCache;
	NSData						*_publicKey;
	dispatch_semaphore_t		_keygenerationsemaphore;
}


#pragma mark Coding

- (void)encodeWithCoder:(NSCoder *)encoder
{
	dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
    
    [encoder encodeObject:_privateKey	forKey:kS_privateKey];
    [encoder encodeObject:_publicKey	forKey:kS_publicKey];
}

- (id)initWithCoder:(NSCoder *)decoder
{
	if( !(self = [super init]) )
	{
		return nil;
	}
	_privateKey	= [decoder decodeObjectForKey:kS_privateKey];
	_publicKey	= [decoder decodeObjectForKey:kS_publicKey];

	return self;
}

#pragma mark Initalisation

+ newWithPassword:(NSData *)passwordData;
{
	return [[self alloc] initWithPassword:passwordData];
}
- initWithPassword:(NSData *)passwordData;
{
	if( !(self = [super init]) )
	{
		return nil;
	}

	_keygenerationsemaphore = dispatch_semaphore_create(0);

	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
	^{
		NSArray	*publicKeyPair = [NSData newPrivatePublicKeyPairWithLength:2048];

        self->_privateKey = [[JNXPasswordProtectedData alloc] initWithData:publicKeyPair[0] password:passwordData];
		self->_publicKey	= publicKeyPair[1];
        dispatch_semaphore_signal(self->_keygenerationsemaphore);
	});
	return self;
}


+ newWithPublicKey:(NSData *)publicKey privateKey:(JNXPasswordProtectedData *)privateKey;
{
	return [[self alloc] initWithPublicKey:(NSData *)publicKey privateKey:(JNXPasswordProtectedData *)privateKey];
}

- initWithPublicKey:(NSData *)publicKey privateKey:(JNXPasswordProtectedData *)privateKey;
{
	if( !(self = [super init]) )
	{
		return nil;
	}
	_publicKey	= [publicKey copy];
	_privateKey	= [privateKey copy];

	return self;
}


#pragma mark Properties


- (NSData *)publicKey;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
	return _publicKey;
}

- (JNXPasswordProtectedData *)privateKey;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
	return _privateKey;
}


#pragma mark PublicKeyEncryption


- (NSData *)encryptData:(NSData *)dataToEncrypt;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
	return [dataToEncrypt encryptWithPublicKey:_publicKey];
}

- (NSData *)decryptData:(NSData *)dataToDecrypt password:(NSData *)passwordData;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
	NSData *decryptedPrivateKey = [_privateKey decryptedDataWithPassword:passwordData];

	NSData *decryptedData = [dataToDecrypt decryptWithPrivateKey:decryptedPrivateKey];
	NSAssert(decryptedData,@"Decryption of data encrypted to private Key failed");
	return decryptedData;
}

- (NSData *)signData:(NSData *)dataToSign password:(NSData *)passwordData;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);
	return [dataToSign signatureWithPrivateKey:[_privateKey decryptedDataWithPassword:passwordData]];
}


#pragma mark Password Caching


- (BOOL)hasCachedPassword
{
	return _privateKeyDataCache ? NO:YES;
}

- (void)deleteCachedPassword
{
	_privateKeyDataCache = nil;
}

- (BOOL)cachePassword:(NSData *)passwordData;
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);

	
	NSData *decryptedPrivateKey = [_privateKey decryptedDataWithPassword:passwordData];

	if( decryptedPrivateKey )
	{
		_privateKeyDataCache = decryptedPrivateKey;
		return YES;
	}
	return NO;
}


#pragma mark Password Caching PublicKeyEncryption


- (NSData *)decryptData:(NSData *)dataToDecrypt
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);

	if( !_privateKeyDataCache )
	{
		DJLog(@"Can't decrypt data - no password cached yet");
		return nil;
	}
	return [dataToDecrypt signatureWithPrivateKey:_privateKeyDataCache];
}


- (NSData *)signData:(NSData *)dataToSign
{
    dispatch_semaphore_wait(self->_keygenerationsemaphore, DISPATCH_TIME_FOREVER);

	if( !_privateKeyDataCache )
	{
		DJLog(@"Can't sign data - no password cached yet");
		return nil;
	}
	return [dataToSign signatureWithPrivateKey:_privateKeyDataCache];
}


@end
