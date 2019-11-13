# SwiftySRP

## Version 4.0
- NOTE: There are breaking changes in this version!
- SwiftySRP no longer depends on FFDataWrapper (which is only used internally for testing).
  Instead, users must provide their own data wrapper class conforming to SRPDataWrapperProtocol when the use create the SRP protocol.
  (It's possible to provide FFDataWrapper there, provided that its conformance to SRPDataWrapperProtocol is declared).
- Eliminated the private imath clang module and its module map. 
   The necessary imath types are declared in SwiftySRP.h, and the functions are bound at runtime via a simple Objective-C binder class.
- Providing data in wrapped form is now mandatory in the methods of SRPProtocol.

## Version 3.0
- Migrated to Swift 5 and removed support for Xcode versions earlier than 10.2
- Removed remaining references to BigInt (in tests)
- Removed unused projects.

## Version 2.13
- Merged pull request #11 (simplified module map)

## Version 2.12
- Swift version changed to 4.2.
- Fixed warnings under Xcode 10.2
- Removed a test which is no longer needed.

## Version 2.11
- Added build setting APPLICATION_EXTENSION_API_ONLY = YES;

## Version 2.10
- Merged pull request with fixes for imath submodule. Thanks, Werner!

## Version 2.9
- Use updated FFDataWrapper.

## Version 2.8
- Use updated FFDataWrapper

## Version 2.7
- Added support for Xcode10. Xcode9 is no longer supported.

## Version 2.6
- Made some classes public.
- Added support for Codable to SRPData.

## Version 2.5
- Renamed CommonCrypto submodule to avoid conflicts under new Xcode.

## Version 2.4
- Added support for Swift 4.1

## Version 2.3
- Bugfix for calculating the server shared key.

## Version 2.2
- Removed BigUInt podspec (because BigUInt is not supported any more.)

## Version 2.1
- BigUInt is no longer supported (because it's very slow)

## Verision 2.0
- APIs now support wrapped parameters (more secure)

## Version 1.0 - 1.1.1
- Initial release.

