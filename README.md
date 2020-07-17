# WIOsense Android Roaming Authenticator

This library provides a FIDO2 roaming authenticator and CTAP1/2 implementation for Android devices. It leverages modern Android OS security concepts to provide easy support for resident keys with strong authentication via biometric user verification or clientPIN functionality compliant with the FIDO2 specification, and so, legacy U2F specification.

The library contains 2 main components, i.e. the `Authenticator` class and the `TransactionManager`. The `Authenticator` implements the authenticator main logic and functionality and can be used directly in any app via the utilities and auxiliary classes existent within the library.

The `TransactionManager` role is to provide an easy way to bind diverse transport layers to the `Authenticator` and handle the CTAP messages and handshakes between a remote client and the authenticator. Currently the `TransactionManager` is focused on handling well the HID CTAP protocol. The physical transport of this can be implemented either via USB connections or the Bluetooth HID device profile and this is up to the calling applications to decide, configure and setup.

An example in this sense is for instance the [WioKey application](https://github.com/wiosense/wiokey-android) which uses the [Bluetooth HID device profile](https://developer.android.com/reference/android/bluetooth/BluetoothHidDevice) available in Android 9.0+ for the communication. We recommend the latter version of implementing HID for an improved user experience and easy interaction support with major desktop platforms (Windows 10, macOS, Linux) out of the box.

For security, the resident keys are protected by default by the Android KeyStore and strong authentication via AndroidX [BiometricPrompt](https://developer.android.com/reference/androidx/biometric/BiometricPrompt) or clientPIN user verfication. Jump to [security](##Security) for more details.

## Quickstart

You can use [JitPack](https://jitpack.io/) to include this module in your Android project, or you can include the source code.

### Using JitPack

Add this in your root build.gradle:

```groovy
    allprojects {
        repositories {
            ...
            maven { url 'https://jitpack.io' }
        }
    }
```
Add this to your dependencies list:

```groovy
    dependencies {
        implementation 'com.github.wiosense:rauth-android:master-SNAPSHOT'
    }
```

### Using Source

#### Pull the source

```
$ cd ~/your/project/src/directory
$ git clone https://github.com/wiosense/rauth-android.git
```

#### Add the module to your Android project

In Android Studio: `File -> New -> Import Module` and then point it at the `rauth-android` directory.

#### Add the module as a dependency

In Android Studio: `File -> Project Structure -> App -> Dependencies -> + -> Module Dependency`

Select the `roaming-authenticator` module. After a Gradle sync, you should be able to use the `de.wiosense.webauthn` package.

## Authenticator.java usage
The `Authenticator` class implements the operations described in the Authenticator API section of Client To Authenticator Protocol [(CTAP)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api), and also provides APIs to manage the credentials that are contained in the Android Keystore.

You must first instantiate an authenticator object, which is safe to instantiate multiple times.

```java
    //Authenticator(Context ctx, boolean strongboxRequired)
    Authenticator roamingAuthenticator = new Authenticator(appContext, true);
```

Here the strongboxRequired flag chooses whether to enforce the usage of a [StrongBox Keymaster](https://developer.android.com/training/articles/keystore#HardwareSecurityModule) HSM. Not all phones support this, but you can easily check at runtime by calling:

```java
    boolean hasStrongbox = currentContext.getPackageManager()
                                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
```

It's important to note that all the following calls are blocking unless stated and shouldn't be executed in the UI thread of the app. Also, from this point on, all mentions to CBOR objects are related to **[this CBOR implementation](https://github.com/c-rack/cbor-java)**.

### GetInfo
You can poll the internal state and capabilities of the authenticator by calling the `Authenticator.getInfo()` method. This returns a `GetInfoResult` object that can be put into CBOR formatted byte array by calling `GetInfoResult.asCBOR`.

### MakeCredential (WebAuthn Registration)
You can create a new credential by passing a `MakeCredentialOptions` object to the `Authenticator.makeCredential` method. Or alternatively, you can also pass a `Map` CBOR object that is formatted according to the CTAP spec, this is usually handled by the internals of the `TransactionManager`.

This will return an `AttestationObject` which you can inspect and retrieve a byte array formatter CBOR like so:

```java
    byte[] attestation = attestationObject.asCBOR();
```

The returned object can be of any of three subclasses depending on the options that were passed to `Authenticator.makeCredentials`:
 * `NoneAttestation`
 * `PackedBasicAttestation`
 * `PackedSelfAttestation`

### GetAssertion (WebAuthn Authentication)
You can make an authentication request by passing a `GetAssertionOptions` object to the `Authenticator.getAssertion` method. Or alternatively, you can also pass a `Map` CBOR object that is formatted according to the CTAP spec, this is usually handleded by the internals of the `TransactionManager`.

This will return an `AssertionObject` which you can inspect and retrieve a byte array formatter CBOR like so:

```java
    byte[] assertion = assertionObject.asCBOR();
```

### GetPinResult (WebAuthn PIN management for higher security requirements)
The `Authenticator.getPinResult` method can be called with a `ClientPINOptions` object. However, it is important to point out that this particular method has a series of subcommands that [internally are handled differently](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN), but all return the same `ClientPINResult` object that can be serialized like the previous results objects. This command is usually used as a [handshake](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#without-pinToken-in-authenticatorGetAssertion), which needs to be handled by the user of the authenticator.

Apart from using the CTAP2 method to manage the PIN, the following APIs are provided for internal management:
* `Authenticator.selfSetPin` which can set a PIN or override a previously set one after user verification
* `Authenticator.resetPin` which gracefully removes a previously set PIN after user verification
* `Authenticator.isPinSet` which returns a boolean specifying whether a PIN is currently set or not.

### Credential Management 
`Authenticator.getAllCredentials` returns a list of all the credentials that are currently stored in the authenticator, as well as their relying parties and other relevant information.  
`Authenticator.deleteCredential` deletes the credential object `PublicKeyCredentialSource` that is passed to it, after user verification.  
`Authenticator.deleteAllCredentials` deletes the credential database after user verification.  
`Authenticator.resetAuthenticator` can be called to completely wipe the credential database as well as the pin, after user verification.  

## TransactionManager.java usage
The `TransactionManager` class oversees all communications going over the Bluetooth connection and is in charge of translating and formatting incoming/outgoing messages in the CTAP1/2 protocols so they can be interpreted by the `Authenticator` class.

The transaction manager needs to be instantiated with a valid `Authenticator` object and a valid activity to pass events like biometric requests to the UI:

```java
    //TransactionManager(FragmentActivity activity, Authenticator authenticator)
    TransactionManager transactionManager = new TransactionManager(currentActivity,
                                                    roamingAuthenticator);
```

To service the messages coming from the Bluetooth connection, the transanction manager needs to be called from the `BluetoothHidDevice.Callback` that is registered to the `inputHost`, which can be done in the following manner:

```java
    BluetoothHidDevice inputHost;
    /* 
     * Perform application registration and initialization
     */
    BluetoothHidDevice.Callback callback = new BluetoothHidDevice.Callback() {
        /*
         * Override other methods
         */
        @Override
        public void onInterruptData(BluetoothDevice device , byte reportId, byte[] data) {
            super.onInterruptData(device, reportId, data);
            transactionManager.handleReport(data, (rawReports) -> {
                for (byte[] report : rawReports) {
                    inputHost.sendReport(device, reportId, report);
                }
            })
        }
    }
```

**NOTE**: In cases where the current activity is recreated, you _must_ update the internal TransactionManager activity by calling `transactionManager.updateActivity(newActivity)`.

## License
The application is open source is released under the terms of [BSD3 license](LICENSE).

Some parts of the code were modified from other open source projects (see [INFO](INFO)), being marked with their original license terms and copyright information.

## Privacy
This library aims to provide a software replacement of hardware security keys by leveraging the modern hardware and security components of Android OS and phones. To this extent all sensitive data is stored on the phone in dedicated secured components and no sensitive information (private keys, user account information) is exchanged with any 3rd parties. It is meant to provide a core authenticator component for FIDO2 strong authentication via roaming authenticators on Android.

## Security
If you identify any security problems or vulnerabilities within this library, please contact vulnerability@wiosense.de with a security disclosure and report of the identified issues.

We practice a fortnight (2 weeks) security disclosure policy, time in which we will try to address the problems and provide a fix. Therefore we kindly ask you to delay any planned public vulnerability disclosure either until 2 weeks have passed or a fix has been issued to allow for this process to take place.

Contributions are of course welcome!

The authenticator operations described earlier handled within the `TransactionManager` are by default protected by strong authentication enforced via screen lock mechanisms (e.g. PIN, pattern, Fingerprint, Face Unlock). It is the responsibility of the caller to make sure such settings exist to enable the authenticator functionality. The credentials database and the client PIN locker are authenticator resident by default and leverage the modern Android OS security hardware capabilities storing the sensitive key materials by default either within a Trusted Execution Environment (TEE) or a dedicated hardware Secure Element (SE) which Android OS asserts to harden and prevent the extraction of the key materials. For a quick distinction between the two check this [article](https://proandroiddev.com/android-keystore-what-is-the-difference-between-strongbox-and-hardware-backed-keys-4c276ea78fd0) out.
