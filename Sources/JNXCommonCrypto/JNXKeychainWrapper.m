//
//  JNXKeychainWrapper.m
//  Keychain2Go
//
//  Created by Stein Patrick on 11-09-12.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

#import "JNXKeychainWrapper.h"
#import "NSString+hexString.h"
#import <Security/Security.h>

#import "JNXLog.h"

@interface JNXKeychainWrapper ()
- (NSData *)dataForKey:(NSString *)key;
- (BOOL)setData:(NSData *)data forKey:(NSString *)key;
- (NSDictionary *)queryDictionaryForKey:(NSString *)key;

@end

@implementation JNXKeychainWrapper


+ (JNXKeychainWrapper *)sharedKeychainWrapper
{	
	static	JNXKeychainWrapper	*sharedKeychainWrapper	= nil;
    static	dispatch_once_t 	onceToken 				= 0;
	
	dispatch_once(&onceToken, 
    ^{
    	sharedKeychainWrapper = [[self alloc] init];
    });                               
	return sharedKeychainWrapper;
}


- (id)init
{
	if( !(self=[super init]) )
    {
    	return nil;
    }
	_processName = [[[NSBundle mainBundle] infoDictionary] objectForKey:(__bridge id)kCFBundleIdentifierKey];

	return self;
}


- (id)objectForKey:(NSString *)key;
{
	NSData 				*dataRead				= [self dataForKey:key];
	if( !dataRead || [dataRead length]==0)
	{
		return nil;
	}
		
    NSError				*error;
    id					retrievedObject			= [NSPropertyListSerialization propertyListWithData:dataRead options:NSPropertyListImmutable format:NULL error:&error];
    
    if( !retrievedObject	)
    {
		DJLog(@"Could not parse propertyList:%@",error);
		return nil;
	}
	return retrievedObject;
}

- (BOOL)setObject:(id)object forKey:(NSString *)key;
{
	NSData 		*propertyListData 	= nil;
	
	if( !object )
	{
		DJLog(@"Will remove key %@ from keychain.",key);
		return [self removeObjectForKey:key];
	}
	
	NSError	*error;
	propertyListData = [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];

	if( !propertyListData )
	{
		JLog(@"Could not create Propertylist due to:%@",error);
		return NO;
	}
	
	return [self setData:propertyListData forKey:key];
}


- (NSDictionary *)queryDictionaryForKey:(NSString *)key
{
	NSString *keyString = [NSString stringWithFormat:@"%@:%@",_processName,key];
	NSMutableDictionary	*itemDictionary = [NSMutableDictionary dictionary];

/* This is disabled as it is incompatible with OSX 10.8 and below.
	[itemDictionary setObject:keyString								forKey:(__bridge id)kSecAttrGeneric];
*/
 	[itemDictionary setObject:keyString								forKey:(__bridge id)kSecAttrLabel];
	[itemDictionary setObject:keyString								forKey:(__bridge id)kSecAttrAccount];
	[itemDictionary setObject:@"" 									forKey:(__bridge id)kSecAttrDescription];
	[itemDictionary setObject:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];

#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	if( _accessGroup )
	{
		[itemDictionary setObject:_accessGroup 							forKey:(__bridge id)kSecAttrAccessGroup];
	}
#endif

	return itemDictionary;
}



- (NSData *)dataForKey:(NSString *)key
{
	NSMutableDictionary *queryDictionary = [[self queryDictionaryForKey:key] mutableCopy];
	
	[queryDictionary setObject:(__bridge id)kSecMatchLimitOne		forKey:(__bridge id)kSecMatchLimit];
	[queryDictionary setObject:(__bridge id)kCFBooleanTrue			forKey:(__bridge id)kSecReturnData];

	CFTypeRef	typeRef;
	OSStatus 	status;
	
	if( noErr == (status = SecItemCopyMatching((__bridge CFDictionaryRef)queryDictionary,&typeRef)) )
	{
   		 NSData *passwordData = [(__bridge NSData *)typeRef copy];
		 CFRelease(typeRef);
		 
		 return passwordData;
	}
	DJLog(@"Did not find item for key:%@ %ld",key,(long)status);
	return nil;
}

- (BOOL)removeObjectForKey:(NSString *)key
{
	NSDictionary *queryDictionary = [self queryDictionaryForKey:key];
	OSStatus	status;

	if( noErr != (status = SecItemDelete((__bridge CFDictionaryRef)queryDictionary)) )
	{
		DJLog(@"Could not delete object:%@",queryDictionary);
		return NO;
	}
	return YES;
}


- (void)deleteItemsWithSearchDictionary:(NSDictionary *)searchDictionary
{
	NSMutableDictionary *deleteDictionary = [searchDictionary mutableCopy];
	
	[deleteDictionary setObject:(__bridge id)kSecClassGenericPassword	forKey:(__bridge id)kSecClass];
	[deleteDictionary setObject:(__bridge id)kSecMatchLimitAll 			forKey:(__bridge id)kSecMatchLimit];
	[deleteDictionary setObject:(__bridge id)kCFBooleanTrue				forKey:(__bridge id)kSecReturnAttributes];
#if TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR
	if( _accessGroup )
	{
		[deleteDictionary setObject:_accessGroup							 	forKey:(__bridge id)kSecAttrAccessGroup];
	}
#endif

	CFTypeRef	typeRef	= NULL;
	OSStatus	status;
	
	if( noErr == (status = SecItemCopyMatching((__bridge CFDictionaryRef)deleteDictionary, (CFTypeRef *)&typeRef)) )
	{
		NSArray	*itemList = (__bridge_transfer id)typeRef;
		
		for( NSDictionary *item in itemList ) 
		{
			NSMutableDictionary *query = [item mutableCopy];
			
			[query setValue:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
			
			[query removeObjectForKey:(__bridge id)kSecAttrModificationDate];
			[query removeObjectForKey:(__bridge id)kSecAttrCreationDate];
			
			if( noErr != (status = SecItemDelete((__bridge CFDictionaryRef)query) ) )
			{
				D2JLog(@"Could not delete item %ld:\n%@\n%@",(long)status,query,searchDictionary);
			}
			else
			{
				D2JLog(@"Deleted item %ld:\n%@\n%@",(long)status,item,deleteDictionary);
			}
		}
	}
}


- (BOOL)setData:(NSData *)data forKey:(NSString *)key
{
	OSStatus 			status;
	NSMutableDictionary	*itemDictionary = [[self queryDictionaryForKey:key] mutableCopy];


	[itemDictionary setObject:data	forKey:(__bridge id)kSecValueData];
	
	if( noErr == (status = SecItemAdd((__bridge CFDictionaryRef)itemDictionary, NULL)) )
	{
		DJLog(@"Sucessfully added item");
		return YES;
	}
    
	if( errSecDuplicateItem == status )
	{
		NSDictionary *queryDictionary = [self queryDictionaryForKey:key];
						
		if( noErr == (status = SecItemUpdate((__bridge CFDictionaryRef)queryDictionary,(__bridge CFDictionaryRef)itemDictionary)) )
		{
			D2JLog(@"Updated item %@",queryDictionary);
			return YES;
		}
		JLog(@"Could not update keychain item:%ld",(long)status);
	}
	else
    {
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
        JLog(@"Could not SecItemAdd Keychain Item: %@ error:%ld",key,(long)status);
#else
        NSString *errorStringA = (__bridge_transfer NSString *)SecCopyErrorMessageString(status,NULL);
        JLog(@"Could not SecItemAdd Keychain Item: %@ error:%ld errorString:%@",key,(long)status,errorStringA);
#endif

    }
    
    
	if( ![self removeObjectForKey:key] )
	{
		JLog(@"Could not remove Keychain Item: %@ error:%ld",key,(long)status);
		return NO;
	}
	
	if( noErr == (status = SecItemAdd((__bridge CFDictionaryRef)itemDictionary, NULL)) )
	{
		return YES;
	}
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    JLog(@"Could not SecItemAdd Keychain Item: %@ error:%ld ",key,(long)status);
#else
    NSString *errorString = (__bridge_transfer NSString *)SecCopyErrorMessageString(status,NULL);
	JLog(@"Could not SecItemAdd Keychain Item: %@ error:%ld errorString:%@",key,(long)status,errorString);
#endif
	return NO;
}








@end
