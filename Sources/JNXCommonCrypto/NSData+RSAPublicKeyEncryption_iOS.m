//
//  NSData+RSAPublicKeyEncryption.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-10.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#ifdef TARGET_OS_IOS

#import "NSData+RSAPublicKeyEncryption.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import "NSData+SHA1.h"
#import "JNXLog.h"

// constants used to find public, private, and symmetric keys.

#define kTypeOfWrapPadding		kSecPaddingPKCS1
#define kTypeOfSigPadding		kSecPaddingPKCS1SHA1
#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH


#define kTemporaryTag			"eu.jinx.keychain.Keychain2Go.temporary"
#define kPublicKeyTag			"eu.jinx.keychain.Keychain2Go.publickey"
#define kPrivateKeyTag			"eu.jinx.keychain.Keychain2Go.privatekey"
#define kSymmetricKeyTag		"eu.jinx.keychain.Keychain2Go.symmetrickey"


static const uint8_t temporaryKeyIdentifier[]	= kTemporaryTag;
static const uint8_t publicKeyIdentifier[]		= kPublicKeyTag;
static const uint8_t privateKeyIdentifier[]		= kPrivateKeyTag;
static const uint8_t symmetricKeyIdentifier[]	= kSymmetricKeyTag;

#define 	temporaryTag	[[NSData alloc] initWithBytes:temporaryKeyIdentifier length:sizeof(temporaryKeyIdentifier)]
#define 	privateTag		[[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)]
#define 	publicTag		[[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)]
#define 	symmetricTag	[[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)]


@implementation NSData (RSAPublicKeyEncryption)



+ (NSArray *)newPrivatePublicKeyPairWithLength:(NSUInteger)keySize;
{
   SecKeyRef publicKeyRef,privateKeyRef;
   
	if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:privateTag	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete private key from keychain"); }
	if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:publicTag 	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete public key from keychain"); }

	NSMutableDictionary * privateKeyAttr	= [[NSMutableDictionary alloc] init];
	NSMutableDictionary * publicKeyAttr		= [[NSMutableDictionary alloc] init];
	NSMutableDictionary * keyPairAttr 		= [[NSMutableDictionary alloc] init];
	
	[keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
	
	[privateKeyAttr setObject:privateTag 					forKey:(__bridge id)kSecAttrApplicationTag];
	[privateKeyAttr setObject:[NSNumber numberWithBool:YES]	forKey:(__bridge id)kSecAttrIsPermanent];

	[publicKeyAttr	setObject:publicTag						forKey:(__bridge id)kSecAttrApplicationTag];
	[publicKeyAttr	setObject:[NSNumber numberWithBool:YES]	forKey:(__bridge id)kSecAttrIsPermanent];

	[keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
	[keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
	
	OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);

	if( errSecSuccess == status )
	{
		NSMutableDictionary *queryKey	= [[NSMutableDictionary alloc] init];

		[queryKey setObject:(__bridge id)kSecClassKey 		forKey:(__bridge id)kSecClass];
		[queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
		[queryKey setObject:publicTag 						forKey:(__bridge id)kSecAttrApplicationTag];
		[queryKey setObject:[NSNumber numberWithBool:YES]	forKey:(__bridge id)kSecReturnData];
		
		
		CFTypeRef	returnTypeRef;
		if( noErr == (status = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, &returnTypeRef)) )
		{
			NSData	*publicKeyData = [(__bridge NSData *)returnTypeRef copy];
			CFRelease(returnTypeRef);
			
			[queryKey setObject:privateTag 						forKey:(__bridge id)kSecAttrApplicationTag];
			if( noErr == (status = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, &returnTypeRef)) )
			{
				NSData	*privateKeyData = [(__bridge NSData *)returnTypeRef copy];
				CFRelease(returnTypeRef);
				
				if( privateKeyData && (privateKeyData.length>=(keySize/8)) && publicKeyData )
				{
//					if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:privateTag	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete private key from keychain"); }
//					if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:publicTag 	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete public key from keychain"); }
				
					CFRelease(privateKeyRef);
					CFRelease(publicKeyRef);
					D2JLog(@"Keys are \nprivate:%@\npublic:%@\n",privateKeyData,publicKeyData);
					
					return [NSArray arrayWithObjects:privateKeyData,publicKeyData, nil];
				}				
				else
				{
					JLog(@"Key have weird size");
					D2JLog(@"Keys are weird size\nprivate:%@\npublic:%@\n",privateKeyData,publicKeyData);
				}
			}
			else
			{
				JLog(@"Could not find private/public key pair SecItemCopyMatching");
			}
		}
		else
		{
			JLog(@"Could not find private/public key pair SecItemCopyMatching");
		}
	}
	else
	{
		JLog(@"Could not generate private/public key pair");
	}
//	if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:privateTag	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete private key from keychain"); }
//	if( noErr == SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:publicTag 	forKey:(__bridge id)kSecAttrApplicationTag]) )	{ JLog(@"Could not delete public key from keychain"); }
	
	return nil;
}



- (SecKeyRef)keyRefFromData:(NSData *)keyData
{
	if( !keyData )
	{
		return NULL;
	}
	
	NSData *sha1Data = [keyData sha1DataNoKey];
	
	SecItemDelete( (__bridge CFDictionaryRef)[NSDictionary dictionaryWithObject:sha1Data forKey:(__bridge id)kSecValueData]);
	
	NSMutableDictionary * attributeDictionary = [[NSMutableDictionary alloc] init];
	
	[attributeDictionary setObject:(__bridge id)kSecClassKey 		forKey:(__bridge id)kSecClass];
	[attributeDictionary setObject:(__bridge id)kSecAttrKeyTypeRSA 	forKey:(__bridge id)kSecAttrKeyType];
	[attributeDictionary setObject:sha1Data							forKey:(__bridge id)kSecAttrApplicationTag];
	[attributeDictionary setObject:keyData							forKey:(__bridge id)kSecValueData];
//	[attributeDictionary setObject:[NSNumber numberWithBool:YES]	forKey:(__bridge id)kSecAttrIsPermanent];
	[attributeDictionary setObject:[NSNumber numberWithBool:YES] 	forKey:(__bridge id)kSecReturnRef];

	SecKeyRef	keyRef;
	OSStatus	status;
	
	status = SecItemDelete( (__bridge CFDictionaryRef)attributeDictionary);
	status = SecItemAdd((__bridge CFDictionaryRef)attributeDictionary, (CFTypeRef *)&keyRef);
	
	if( noErr == status )
	{
	//	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&keyRef);

		
		return keyRef;
	}
	return NULL;
}


- (SecKeyRef)privateKeyRef
{
	OSStatus 	status;
	SecKeyRef	keyRef	 = NULL;
	NSMutableDictionary * attributeDictionary = [[NSMutableDictionary alloc] init];
	
	[attributeDictionary setObject:(__bridge id)kSecClassKey 		forKey:(__bridge id)kSecClass];
	[attributeDictionary setObject:(__bridge id)kSecAttrKeyTypeRSA 	forKey:(__bridge id)kSecAttrKeyType];
	[attributeDictionary setObject:privateTag						forKey:(__bridge id)kSecAttrApplicationTag];
	[attributeDictionary setObject:[NSNumber numberWithBool:YES] 	forKey:(__bridge id)kSecReturnRef];
	
	if( noErr != (status = SecItemCopyMatching((__bridge CFDictionaryRef)attributeDictionary,(CFTypeRef *)&keyRef)) )
	{
		return nil;
	}
	return keyRef;
}



- (NSData *)encryptWithPublicKey:(NSData *)publicKeyData
{
	SecKeyRef	keyRef = [self keyRefFromData:publicKeyData];
	
	if( !keyRef )
	{
		return nil;
	}
	
	
	size_t 	cipherBufferSize 	= SecKeyGetBlockSize(keyRef);
	uint8_t	cipherBuffer[4048]	= {0};

	OSStatus status;
	
	if( noErr == (status = SecKeyEncrypt(keyRef,	kTypeOfWrapPadding,	(const uint8_t *)[self bytes],[self length],cipherBuffer,&cipherBufferSize)) )
	{
		CFRelease(keyRef);
		return [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
	}
	CFRelease(keyRef);
	return nil;
}


- (NSData *)decryptWithPrivateKey:(NSData *)privateKeyData
{
	SecKeyRef	keyRef	 = [self privateKeyRef];
	
	if( !keyRef )
	{
		return nil;
	}

	uint8_t	cipherBuffer[2048]	= {0};
	size_t	cipherBufferSize	= sizeof(cipherBuffer);
	OSStatus status;
	
	if( noErr == (status = SecKeyDecrypt(keyRef,	kTypeOfWrapPadding,	(const uint8_t *)[self bytes],self.length,cipherBuffer,&cipherBufferSize)) )
	{	
		CFRelease(keyRef);
		return [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
	}
	CFRelease(keyRef);
	return nil;
}



- (NSData *)signatureWithPrivateKey:(NSData *)privateKeyData
{
	SecKeyRef	keyRef	 = [self privateKeyRef];
	
	if( !keyRef )
	{
		return nil;
	}
	
	NSData	*sha1Data = [self sha1DataNoKey];
	
	
	uint8_t	signedHashBytes[2048]	= {0};
	size_t	signedHashBytesSize		= sizeof(signedHashBytes);

	OSStatus status;
	if( noErr == (status = SecKeyRawSign(	keyRef, 	kTypeOfSigPadding,	(const uint8_t *)[sha1Data bytes], [sha1Data length], (uint8_t *)signedHashBytes, &signedHashBytesSize)) )
	{	
		CFRelease(keyRef);
		return [NSData dataWithBytes:signedHashBytes length:signedHashBytesSize];
	}
	CFRelease(keyRef);
	return nil;
}



- (BOOL)verifyRSASignature:(NSData *)signatureData withPublicKey:(NSData *)publicKeyData;
{
	if( !publicKeyData || !signatureData)
	{
		return NO;
	}
	SecKeyRef	keyRef = [self keyRefFromData:publicKeyData];
	
	if( !keyRef )
	{
		return NO;
	}
	NSData	*sha1Data = [self sha1DataNoKey];

	OSStatus status;
	if( noErr == (status = SecKeyRawVerify(	keyRef, kTypeOfSigPadding, 	(const uint8_t *)[sha1Data bytes],	[sha1Data length], 	(const uint8_t *)[signatureData bytes],	[signatureData length]	) ) )
	{
		CFRelease(keyRef);
		return YES;
	}

	CFRelease(keyRef);
	return NO;
}

@end



#endif




