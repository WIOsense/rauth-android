package de.wiosense.webauthn.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import de.wiosense.webauthn.exceptions.VirgilException;

public class ClientPinLocker {
    private static final String TAG = "ClientPINEntry";

    private static final String KEYSTORE_TYPE = "AndroidKeyStore";
    private static final String CLIENT_PIN_TYPE = "Android_ePIN_";

    private static final String CLIENT_PIN_FIELD_PIN_RETRIES = "RETRIES";
    private static final int CLIENT_PIN_FIELD_PIN_RETRIES_VALUE = 0;

    private static final String CLIENT_PIN_FIELD_PIN_TOKEN = "TOKEN";
    private static final String CLIENT_PIN_FIELD_PIN_TOKEN_VALUE = "";

    private static final String CLIENT_PIN_FIELD_PIN_SHA256 = "PIN-SHA256";
    private static final String CLIENT_PIN_FIELD_PIN_SHA256_VALUE = "";

    private static final int PIN_TOKEN_LENGTH = 16;

    private SharedPreferences locker;
    private String clientId;
    private String cpkAlias;
    private String lockerId;

    public ClientPinLocker(Context ctx, @NonNull byte[] clientData) throws VirgilException {
        this(ctx, clientData, true);
    }

    public ClientPinLocker(Context ctx,
                    @NonNull byte[] clientData,
                    boolean strongboxRequired) throws VirgilException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new VirgilException("Failed to hash data", e);
        }
        md.update(clientData);
        this.clientId = bytesToHexString(md.digest());
        this.cpkAlias = "cpk" + this.clientId;
        this.lockerId = CLIENT_PIN_TYPE + this.clientId;

        // Create now an encrypted enclosure to store the client ID metadata (retries / pinToken)
        MasterKey masterKey;
        try {
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                    cpkAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setIsStrongBoxBacked(strongboxRequired)
                    .setUnlockedDeviceRequired(true)
                    .build();
            MasterKey.Builder masterKeyBuilder = new MasterKey.Builder(ctx, cpkAlias);
            masterKey = masterKeyBuilder.setKeyGenParameterSpec(keySpec).build();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
            throw new VirgilException("Could not initialize clientPIN safe key");
        }

        try {
            locker = EncryptedSharedPreferences.create(
                    ctx,
                    lockerId,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
            throw new VirgilException("Could not initialize clientPIN safe");
        }

        refreshToken();
    }

    public ClientPinLocker setRetries(long retries) {
        if (retries < 0 || retries > 8) return this;
        locker.edit()
                .putLong(CLIENT_PIN_FIELD_PIN_RETRIES, retries)
                .apply();
        return this;
    }

    public ClientPinLocker setToken(@NonNull byte[] token) {
        if (token.length % 16 != 0) return this;

        String tokenString = bytesToHexString(token);
        locker.edit()
                .putString(CLIENT_PIN_FIELD_PIN_TOKEN, tokenString)
                .apply();
        return this;
    }

    public boolean lockPin(@NonNull byte[] pin) {
        String pinString = bytesToHexString(pin);
        try {
            refreshToken();
        } catch (VirgilException e) {
            Log.w(TAG, "Failed to refresh token on this occasion!");
        }
        return locker.edit()
                .putString(CLIENT_PIN_FIELD_PIN_SHA256, pinString)
                .commit();
    }

    public boolean isPinMatch(@NonNull byte[] pinTry) {
        String pinTryString = bytesToHexString(pinTry);
        String pinReference = locker.getString(CLIENT_PIN_FIELD_PIN_SHA256,
                CLIENT_PIN_FIELD_PIN_SHA256_VALUE);

        if (pinReference.equals(CLIENT_PIN_FIELD_PIN_SHA256_VALUE)) return false;

        return pinReference.equals(pinTryString);
    }

    public boolean isPinSet() {
        String pinReference = locker.getString(CLIENT_PIN_FIELD_PIN_SHA256,
                CLIENT_PIN_FIELD_PIN_SHA256_VALUE);

        return !pinReference.equals(CLIENT_PIN_FIELD_PIN_SHA256_VALUE);
    }

    public boolean resetPinLocker() {
        return locker.edit()
                .putLong(CLIENT_PIN_FIELD_PIN_RETRIES, CLIENT_PIN_FIELD_PIN_RETRIES_VALUE)
                .putString(CLIENT_PIN_FIELD_PIN_TOKEN, CLIENT_PIN_FIELD_PIN_TOKEN_VALUE)
                .putString(CLIENT_PIN_FIELD_PIN_SHA256, CLIENT_PIN_FIELD_PIN_SHA256_VALUE)
                .commit();
    }

    @NotNull
    @Override
    public String toString() {
        return this.clientId;
    }

    public Long getRetries() {
        return locker.getLong(CLIENT_PIN_FIELD_PIN_RETRIES, CLIENT_PIN_FIELD_PIN_RETRIES_VALUE);
    }

    public @Nullable byte[] getToken() {
        String tokenString = locker.getString(CLIENT_PIN_FIELD_PIN_TOKEN,
                CLIENT_PIN_FIELD_PIN_TOKEN_VALUE);

        if (!tokenString.equals(CLIENT_PIN_FIELD_PIN_TOKEN_VALUE)) {
            return hexStringToBytes(tokenString);
        } else {
            return null;
        }
    }

    public void deletePinLocker() throws VirgilException, KeyStoreException {
        /*
         * This is done by clearing all the fields, committing all the changes
         * and then removing the sharedPreferences files as per
         * https://stackoverflow.com/questions/6125296/delete-sharedpreferences-file
         * or
         * https://github.com/akaita/encryptedsharedpreferences-example/blob/master/app/src/main/java/com/akaita/encryptedsharedpreferences/MainActivity.kt#L123
         *
         * Also at the end removing the key from the keyStore if possible
         */
        locker.edit().clear().commit();
        this.getClass().getPackage();

        String lockerUri = getLockerUri();

        File locker = new File(lockerUri);
        if (locker.exists()) {
            try {
                locker.delete();
            } catch (SecurityException e) {
                throw new VirgilException("Couldn't delete locker", e);
            }
        }

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException |
                NoSuchAlgorithmException | IOException e) {
            throw new VirgilException("Couldn't access keystore", e);
        }

        keyStore.deleteEntry(cpkAlias);
    }

    public void decrementPinRetries() throws VirgilException {
        long retries = locker.getLong(CLIENT_PIN_FIELD_PIN_RETRIES, CLIENT_PIN_FIELD_PIN_RETRIES_VALUE);
        if (retries != 0) {
            retries--;
            locker.edit().putLong(CLIENT_PIN_FIELD_PIN_RETRIES, retries).commit();
        } else {
            throw new VirgilException("Client PIN error");
        }
    }

    public void refreshToken() throws VirgilException {
        try{
            byte[] pinToken = new byte[PIN_TOKEN_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(pinToken);
            this.setToken(pinToken);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new VirgilException("Cannot produce pinToken bits", e);
        }
    }

    private String getLockerUri() {
        ApplicationInfo appInfo = new ApplicationInfo();
        return appInfo.dataDir + "/shared_prefs/" + lockerId + ".xml";
    }

    private String bytesToHexString(@NonNull byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private @Nullable byte[] hexStringToBytes(String str) {
        int len = str.length();
        if (len == 0) return null;

        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
                    + Character.digit(str.charAt(i+1), 16));
        }
        return bytes;
    }
}
