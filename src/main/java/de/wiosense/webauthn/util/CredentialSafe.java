package de.wiosense.webauthn.util;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.util.Pair;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import androidx.annotation.RequiresApi;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import de.wiosense.webauthn.exceptions.VirgilException;
import de.wiosense.webauthn.models.PublicKeyCredentialSource;
import de.wiosense.webauthn.util.database.CredentialDatabase;


/**
 * CredentialSafe uses the Android KeyStore to generate and store
 * ES256 keys that are hardware-backed.
 * <p>
 * These keys can optionally be protected with "Strongbox keymaster" protection and user
 * authentication on supported hardware.
 */
public class CredentialSafe {
    private static final String KEYSTORE_TYPE = "AndroidKeyStore";
    private static final String CURVE_NAME = "secp256r1";
    private KeyStore keyStore;
    public boolean biometricSigningSupported;
    private boolean strongboxRequired;
    private CredentialDatabase db;

    private final static String TAG = "CredentialSafe";

    /**
     * Construct a CredentialSafe that requires user authentication and strongbox backing.
     *
     * @param ctx The application context
     * @throws VirgilException
     */
    public CredentialSafe(Context ctx) throws VirgilException {
        this(ctx, true);
    }

    /**
     * Construct a CredentialSafe with configurable user authentication / strongbox choices.
     *
     * @param ctx                    The application context
     * @param strongboxRequired      Require keys to be backed by the "Strongbox Keymaster" HSM.
     *                               Requires hardware support.
     * @throws VirgilException
     */
    public CredentialSafe(Context ctx, boolean strongboxRequired) throws VirgilException {
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException |
                NoSuchAlgorithmException | IOException e) {
            throw new VirgilException("couldn't access keystore", e);
        }

//        BiometricManager biometricManager = BiometricManager.from(ctx);
//        this.biometricSigningSupported = (biometricManager.canAuthenticate()
//                                    == BiometricManager.BIOMETRIC_SUCCESS);
        this.biometricSigningSupported = false; // Biometric signing is always disabled as we give
                                                // users the option to verify themselves using PIN/Pattern
        this.strongboxRequired = strongboxRequired;
        this.db = CredentialDatabase.getDatabase(ctx);
    }

    /**
     * Generate a new ES256 keypair (COSE algorithm -7, ECDSA + SHA-256 over the NIST P-256 curve).
     *
     * @param alias The alias used to identify this keypair in the keystore. Needed to use key
     *              in the future.
     * @return The KeyPair object representing the newly generated keypair.
     * @throws VirgilException
     */
    @RequiresApi(api = Build.VERSION_CODES.P)
    public KeyPair generateNewES256KeyPair(String alias) throws VirgilException {
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(CURVE_NAME))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(120)
                .setUserConfirmationRequired(false)
                .setInvalidatedByBiometricEnrollment(false)
                .setIsStrongBoxBacked(this.strongboxRequired)
                .build();
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_TYPE);
            keyPairGenerator.initialize(spec);

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new VirgilException("couldn't generate key pair: " + e.toString());
        }
    }

    /**
     * Generate and save new credential with an ES256 keypair.
     *
     * @param rpEntityId      The relying party's identifier
     * @param rpDisplayName         A human-readable display name for the user
     * @param u2fRpId               Native U2F domain
     * @return A PublicKeyCredentialSource object corresponding to the new keypair and its associated
     * rpId, credentialId, etc.
     * @throws VirgilException
     */
    public PublicKeyCredentialSource generateCredential(@NonNull String rpEntityId, String rpDisplayName,
                                                        @NonNull String u2fRpId) throws VirgilException {
        return generateCredential(rpEntityId, rpDisplayName, null, new byte[4], null, false, u2fRpId);
    }

    /**
     * Generate and save new credential with an ES256 keypair.
     *
     * @param rpEntityId            The relying party's identifier
     * @param rpDisplayName         A human-readable display name for the user
     * @param rpIcon                The relying party icon URL
     * @param userHandle            A unique ID for the user
     * @param userDisplayName       A human-readable username for the user
     * @param generateHmacSecret    Wether an HMAC symmetric key should be genereated
     * @return A PublicKeyCredentialSource object corresponding to the new keypair and its associated
     * rpId, credentialId, etc.
     * @throws VirgilException
     */
    public PublicKeyCredentialSource generateCredential(@NonNull String rpEntityId, String rpDisplayName,
                                                        String rpIcon, byte[] userHandle,
                                                        String userDisplayName, boolean generateHmacSecret) throws VirgilException {
        return generateCredential(rpEntityId, rpDisplayName, rpIcon, userHandle, userDisplayName, generateHmacSecret, null);
    }

    /**
     * Generate and save new credential with an ES256 keypair.
     *
     * @param rpEntityId            The relying party's identifier
     * @param rpDisplayName         A human-readable display name for the user
     * @param rpIcon                The relying party icon URL
     * @param userHandle            A unique ID for the user
     * @param userDisplayName       A human-readable username for the user
     * @param generateHmacSecret    Wether an HMAC symmetric key should be genereated
     * @param u2fRpId               Native U2F domain
     * @return A PublicKeyCredentialSource object corresponding to the new keypair and its associated
     * rpId, credentialId, etc.
     * @throws VirgilException
     */
    public PublicKeyCredentialSource generateCredential(@NonNull String rpEntityId, String rpDisplayName,
                                                        String rpIcon, byte[] userHandle,
                                                        String userDisplayName, boolean generateHmacSecret,
                                                        String u2fRpId) throws VirgilException {
        PublicKeyCredentialSource credentialSource;
        credentialSource = new PublicKeyCredentialSource(rpEntityId, rpDisplayName, rpIcon,
                                                         userHandle, userDisplayName,
                                                         generateHmacSecret, u2fRpId);

        generateNewES256KeyPair(credentialSource.keyPairAlias); // return not captured -- will retrieve credential by alias
        SecretKey symmetricKey = null;
        if (generateHmacSecret) {
            KeyGenParameterSpec.Builder hmacParameterSpec = new KeyGenParameterSpec.Builder(
                    credentialSource.hmacSecretAlias, KeyProperties.PURPOSE_SIGN);
            hmacParameterSpec.setDigests(KeyProperties.DIGEST_SHA256);
            hmacParameterSpec.setKeySize(256);
            symmetricKey = generateSymmetricKey(KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
                                                        hmacParameterSpec);
        }

        db.credentialDao().insert(credentialSource);

        if (generateHmacSecret && (symmetricKey == null)) {
            deleteCredential(credentialSource);
            return null;
        }

        return credentialSource;
    }

    public SecretKey generateSymmetricKey(String algorithm, KeyGenParameterSpec.Builder builder) {
        try {
            KeyGenerator kpg = KeyGenerator.getInstance(algorithm, KEYSTORE_TYPE);
            KeyGenParameterSpec parameterSpec = builder.build();
            kpg.init(parameterSpec);
            return kpg.generateKey();
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate symmetric key:");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Deletes a single credential
     *
     * @param credentialSource  Credential to be deleted
     */
    public void deleteCredential(PublicKeyCredentialSource credentialSource) {
        db.credentialDao().delete(credentialSource);
    }

    /**
     * Wipes out all credentials in credentialList
     *
     * @param credentialList Credentials to be deleted
     */
    public void deleteAllCredentials(List<PublicKeyCredentialSource> credentialList) {
        for (PublicKeyCredentialSource credential: credentialList){
            db.credentialDao().delete(credential);
        }
    }

    /**
     * Wipes out ALL credentials in the storage
     */
    public void deleteAllCredentials() {
        List<PublicKeyCredentialSource> temp = getAllCredentials();
        deleteAllCredentials(temp);
    }

    /**
     *
     * @return All credentials registered
     */
    public List<PublicKeyCredentialSource> getAllCredentials() {
        return db.credentialDao().getAll();
    }

    /**
     * Get keys belonging to this RP ID.
     *
     * @param rpEntityId rpEntity.id from WebAuthn spec.
     * @return The set of associated PublicKeyCredentialSources.
     */
    public List<PublicKeyCredentialSource> getKeysForEntity(@NonNull String rpEntityId) {
        return db.credentialDao().getAllByRpId(rpEntityId);
    }

    /**
     * Get the credential matching the specified id, if it exists
     *
     * @param id byte[] credential id
     * @return PublicKeyCredentialSource that matches the id, or null
     */
    public PublicKeyCredentialSource getCredentialSourceById(@NonNull byte[] id) {
        return db.credentialDao().getById(id);
    }


    /**
     * Retrieve a previously-generated keypair from the keystore.
     *
     * @param alias The associated keypair alias.
     * @return A KeyPair object representing the public/private keys. Private key material is
     * not accessible.
     * @throws VirgilException
     */
    public KeyPair getKeyPairByAlias(@NonNull String alias) throws VirgilException {
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new VirgilException("couldn't get key by alias", e);
        }
    }

    public SecretKey getSecretKeyByAlias(@NonNull String alias) throws VirgilException {
        try {
            return (SecretKey) keyStore.getKey(alias, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new VirgilException("couldn't get key by alias", e);
        }
    }

    /**
     * Checks whether this key requires user verification or not
     *
     * @param alias The associated keypair alias
     * @return whether this key requires user verification or not
     * @throws VirgilException
     */
    public boolean keyRequiresVerification(@NonNull String alias) throws VirgilException {
        PrivateKey privateKey = getKeyPairByAlias(alias).getPrivate();
        KeyFactory factory;
        KeyInfo keyInfo;

        try {
            factory = KeyFactory.getInstance(privateKey.getAlgorithm(), KEYSTORE_TYPE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException exception) {
            throw new VirgilException("Couldn't build key factory: " + exception.toString());
        }

        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException exception) {
            throw new VirgilException("Not an android keystore key: " + exception.toString());
        }

        return keyInfo.isUserAuthenticationRequired();
    }

    /**
     * Checks whether all certificates are stored in hardware
     * @return true iff all credentials are in hardware
     *         false if at least one of the credentials is not in hardware
     *         null if there are no credentials or the operation failed
     */
    public Boolean credentialsInHardware() {
        try {
            List<String> aliases = java.util.Collections.list(keyStore.aliases());
            if (aliases.isEmpty()) {
                return null; // Empty return
            }

            for (String alias: aliases) {
                Key key = keyStore.getKey(alias, null);
                KeyInfo keyInfo;
                if (key instanceof SecretKey) {
                    SecretKeyFactory secretFactory = SecretKeyFactory.getInstance(
                                                                key.getAlgorithm(),
                                                                KEYSTORE_TYPE);
                    keyInfo = (KeyInfo)secretFactory.getKeySpec((SecretKey)key, KeyInfo.class);
                } else if (key instanceof PrivateKey) {
                    KeyFactory keyFactory = KeyFactory.getInstance(
                                                key.getAlgorithm(),
                                                KEYSTORE_TYPE);
                    keyInfo = keyFactory.getKeySpec(key, KeyInfo.class);
                } else {
                    return false;
                }

                if (!keyInfo.isInsideSecureHardware() || keyInfo.getOrigin() != KeyProperties.ORIGIN_GENERATED) {
                    return false;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return true;
    }

    /**
     * Fix the length of a byte array such that:
     * 1) If the desired length is less than the length of `arr`, the left-most source bytes are
     * truncated.
     * 2) If the desired length is more than the length of `arr`, the left-most destination bytes
     * are set to 0x00.
     *
     * @param arr         The source byte array.
     * @param fixedLength The desired length of the resulting array.
     * @return A new array of length fixedLength.
     */
    private static byte[] toUnsignedFixedLength(byte[] arr, int fixedLength) {
        byte[] fixed = new byte[fixedLength];
        int offset = fixedLength - arr.length;
        int srcPos = Math.max(-offset, 0);
        int dstPos = Math.max(offset, 0);
        int copyLength = Math.min(arr.length, fixedLength);
        System.arraycopy(arr, srcPos, fixed, dstPos, copyLength);
        return fixed;
    }

    /**
     * Encode an EC public key in the COSE/CBOR format.
     *
     * @param publicKey The public key.
     * @return A COSE_Key-encoded public key as byte array.
     * @throws VirgilException
     */
    public static byte[] coseEncodePublicKey(PublicKey publicKey) throws VirgilException {
        Pair<byte[], byte[]> point = cosePointEncode(publicKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            new CborEncoder(baos).encode(new CborBuilder()
                    .addMap()
                    .put(1, 2)              // kty: EC2 key type
                    .put(3, -7)             // alg: ES256 sig algorithm
                    .put(-1, 1)             // crv: P-256 curve
                    .put(-2, point.first)   // x-coord
                    .put(-3, point.second)  // y-coord
                    .end()
                    .build()
            );
        } catch (CborException e) {
            throw new VirgilException("couldn't serialize to cbor", e);
        }
        return baos.toByteArray();
    }

    /**
     * Perform first part of cose encoding and validation
     *
     * @param publicKey The public key.
     * @return byte array "byte[]" pair where x is first and y is second
     */
   public static Pair<byte[], byte[]> cosePointEncode(PublicKey publicKey) {
       ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
       ECPoint point = ecPublicKey.getW();
       // ECPoint coordinates are *unsigned* values that span the range [0, 2**32). The getAffine
       // methods return BigInteger objects, which are signed. toByteArray will output a byte array
       // containing the two's complement representation of the value, outputting only as many
       // bytes as necessary to do so. We want an unsigned byte array of length 32, but when we
       // call toByteArray, we could get:
       // 1) A 33-byte array, if the point's unsigned representation has a high 1 bit.
       //    toByteArray will prepend a zero byte to keep the value positive.
       // 2) A <32-byte array, if the point's unsigned representation has 9 or more high zero
       //    bits.
       // Due to this, we need to either chop off the high zero byte or prepend zero bytes
       // until we have a 32-length byte array.
       byte[] xVariableLength = point.getAffineX().toByteArray();
       byte[] yVariableLength = point.getAffineY().toByteArray();

       byte[] x = toUnsignedFixedLength(xVariableLength, 32);
       assert x.length == 32;
       byte[] y = toUnsignedFixedLength(yVariableLength, 32);
       assert y.length == 32;

       return new Pair<>(x, y);
   }


    /**
     * Increment the credential use counter for this credential.
     *
     * @param credential The credential whose counter we want to increase.
     * @return The value of the counter before incrementing.
     */
    public int incrementCredentialUseCounter(PublicKeyCredentialSource credential) {
        return db.credentialDao().incrementUseCounter(credential);
    }

    public KeyPair keyAgreementPair() throws NoSuchAlgorithmException,
                                             InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE_NAME);
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(ecGenParameterSpec);
        return keyPairGen.genKeyPair();
    }
}
