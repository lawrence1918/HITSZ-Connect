//go:build darwin && cgo

package secureconfig

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef hc_string(const char *value) {
	if (value == NULL) {
		return NULL;
	}
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFDictionaryRef hc_query(CFStringRef service, CFStringRef account, Boolean returnData) {
	const void *keys[4];
	const void *values[4];
	CFIndex count = 3;
	keys[0] = kSecClass;
	values[0] = kSecClassGenericPassword;
	keys[1] = kSecAttrService;
	values[1] = service;
	keys[2] = kSecAttrAccount;
	values[2] = account;
	if (returnData) {
		keys[3] = kSecReturnData;
		values[3] = kCFBooleanTrue;
		count = 4;
	}
	return CFDictionaryCreate(kCFAllocatorDefault, keys, values, count,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static OSStatus hc_get_secret(const char *serviceValue, const char *accountValue,
		unsigned char **out, CFIndex *outLength) {
	if (out == NULL || outLength == NULL) {
		return errSecParam;
	}
	*out = NULL;
	*outLength = 0;
	CFStringRef service = hc_string(serviceValue);
	CFStringRef account = hc_string(accountValue);
	if (service == NULL || account == NULL) {
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecAllocate;
	}
	CFDictionaryRef query = hc_query(service, account, true);
	CFRelease(service);
	CFRelease(account);
	if (query == NULL) {
		return errSecAllocate;
	}
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) {
		return status;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecInternalComponent;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	unsigned char *copy = (unsigned char *)malloc(length > 0 ? (size_t)length : 1);
	if (copy == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	if (length > 0) {
		memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
	}
	CFRelease(result);
	*out = copy;
	*outLength = length;
	return errSecSuccess;
}

static OSStatus hc_set_secret(const char *serviceValue, const char *accountValue,
		const unsigned char *secret, CFIndex secretLength) {
	if (secret == NULL || secretLength <= 0) {
		return errSecParam;
	}
	CFStringRef service = hc_string(serviceValue);
	CFStringRef account = hc_string(accountValue);
	if (service == NULL || account == NULL) {
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecAllocate;
	}
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, secret, secretLength);
	if (data == NULL) {
		CFRelease(service);
		CFRelease(account);
		return errSecAllocate;
	}
	CFMutableDictionaryRef item = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (item == NULL) {
		CFRelease(data);
		CFRelease(service);
		CFRelease(account);
		return errSecAllocate;
	}
	CFDictionarySetValue(item, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(item, kSecAttrService, service);
	CFDictionarySetValue(item, kSecAttrAccount, account);
	CFDictionarySetValue(item, kSecValueData, data);
	OSStatus status = SecItemAdd(item, NULL);
	CFRelease(item);
	if (status == errSecDuplicateItem) {
		CFDictionaryRef query = hc_query(service, account, false);
		CFMutableDictionaryRef updates = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		if (query == NULL || updates == NULL) {
			if (query != NULL) CFRelease(query);
			if (updates != NULL) CFRelease(updates);
			status = errSecAllocate;
		} else {
			CFDictionarySetValue(updates, kSecValueData, data);
			status = SecItemUpdate(query, updates);
			CFRelease(query);
			CFRelease(updates);
		}
	}
	CFRelease(data);
	CFRelease(service);
	CFRelease(account);
	return status;
}

static OSStatus hc_delete_secret(const char *serviceValue, const char *accountValue) {
	CFStringRef service = hc_string(serviceValue);
	CFStringRef account = hc_string(accountValue);
	if (service == NULL || account == NULL) {
		if (service != NULL) CFRelease(service);
		if (account != NULL) CFRelease(account);
		return errSecAllocate;
	}
	CFDictionaryRef query = hc_query(service, account, false);
	CFRelease(service);
	CFRelease(account);
	if (query == NULL) {
		return errSecAllocate;
	}
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}

static void hc_free_secret(void *secret, CFIndex secretLength) {
	if (secret != NULL) {
		if (secretLength > 0) {
			memset(secret, 0, (size_t)secretLength);
		}
		free(secret);
	}
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

const errSecItemNotFound = -25300

// KeychainProvider stores one AES-256 data encryption key for each encrypted
// profile in the logged-in user's macOS Keychain.
type KeychainProvider struct {
	service string
}

// NewKeychainProvider returns the production macOS Keychain implementation.
// It communicates with Security.framework directly; no secret is sent through
// argv, an environment variable, or a temporary plaintext file.
func NewKeychainProvider() (KeyProvider, error) {
	return &KeychainProvider{service: KeychainService}, nil
}

// Get returns the 32-byte key for a profile.
func (provider *KeychainProvider) Get(id string) ([]byte, error) {
	if err := validateID(id); err != nil {
		return nil, err
	}
	service := C.CString(provider.service)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(id)
	defer C.free(unsafe.Pointer(account))

	var secret *C.uchar
	var length C.CFIndex
	status := C.hc_get_secret(service, account, &secret, &length)
	if status != 0 {
		if int(status) == errSecItemNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, keychainStatusError("get", int(status))
	}
	defer C.hc_free_secret(unsafe.Pointer(secret), length)
	if secret == nil || length != C.CFIndex(keyLength) {
		return nil, errorsInvalidKeychainKey()
	}
	key := C.GoBytes(unsafe.Pointer(secret), C.int(length))
	return key, nil
}

// Set creates or replaces the key for a profile.
func (provider *KeychainProvider) Set(id string, key []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	if err := validateKey(key); err != nil {
		return err
	}
	service := C.CString(provider.service)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(id)
	defer C.free(unsafe.Pointer(account))

	status := C.hc_set_secret(service, account, (*C.uchar)(unsafe.Pointer(&key[0])), C.CFIndex(len(key)))
	runtime.KeepAlive(key)
	if status != 0 {
		return keychainStatusError("set", int(status))
	}
	return nil
}

// Delete removes the key for a profile.
func (provider *KeychainProvider) Delete(id string) error {
	if err := validateID(id); err != nil {
		return err
	}
	service := C.CString(provider.service)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(id)
	defer C.free(unsafe.Pointer(account))

	status := C.hc_delete_secret(service, account)
	if status != 0 {
		if int(status) == errSecItemNotFound {
			return ErrKeyNotFound
		}
		return keychainStatusError("delete", int(status))
	}
	return nil
}

func keychainStatusError(operation string, status int) error {
	return fmt.Errorf("secureconfig: macOS Keychain %s failed (status %d)", operation, status)
}

func errorsInvalidKeychainKey() error {
	return fmt.Errorf("secureconfig: macOS Keychain returned a key with invalid length")
}
