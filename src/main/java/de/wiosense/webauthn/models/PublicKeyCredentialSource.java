package de.wiosense.webauthn.models;

import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.Index;
import androidx.room.PrimaryKey;
import androidx.annotation.NonNull;
import android.util.Base64;

import java.security.SecureRandom;

@Entity(tableName = "credentials", indices = {@Index("rpId")})
public class PublicKeyCredentialSource {
    public static final String type = "public-key";

    @PrimaryKey(autoGenerate = true)
    public int roomUid;
    public byte[] id;
    public String keyPairAlias;
    public String hmacSecretAlias;
    public String rpId;
    public String rpDisplayName;
    public String u2fRpId;
    public String rpIcon;
    public byte[] userHandle;
    public String userDisplayName;
    public String otherUI;
    public int keyUseCounter;
    public boolean generateHmacSecret;

    @Ignore
    private static SecureRandom random;
    @Ignore
    private static final String KEYPAIR_PREFIX = "virgil-keypair-";
    @Ignore
    private static final String HMAC_SECRET_PREFIX = "virgil-hmac-secret-keypair-";

    /**
     * Construct a new PublicKeyCredentialSource. This is the canonical object that represents a
     * WebAuthn credential.
     *
     * @param rpId                  The relying party ID.
     * @param rpDisplayName         A human-readable display name for the user
     * @param rpIcon                The relying party icon URL
     * @param userHandle            The unique ID used by the RP to identify the user.
     * @param userDisplayName       A human-readable display name for the user.
     * @param generateHmacSecret    Generate hmacSecret
     * @param u2fRpId               Native U2F domain
     */
    public PublicKeyCredentialSource(@NonNull String rpId, String rpIcon, String rpDisplayName,
                                     byte[] userHandle, String userDisplayName, boolean generateHmacSecret,
                                     String u2fRpId) {
        ensureRandomInitialized();
        this.id = new byte[32];
        this.userDisplayName = userDisplayName;
        this.userHandle = userHandle;
        PublicKeyCredentialSource.random.nextBytes(this.id);

        this.rpId = rpId;
        this.rpDisplayName = rpDisplayName;
        this.u2fRpId = u2fRpId;
        this.rpIcon = rpIcon;
        this.keyPairAlias = KEYPAIR_PREFIX + Base64.encodeToString(id, Base64.NO_WRAP);
        this.keyUseCounter = 1;

        this.generateHmacSecret = generateHmacSecret;
        if (generateHmacSecret) {
            this.hmacSecretAlias = HMAC_SECRET_PREFIX + Base64.encodeToString(id, Base64.NO_WRAP);
        } else {
            this.hmacSecretAlias = null;
        }
    }

    /**
     * Ensure the SecureRandom singleton has been initialized.
     */
    private void ensureRandomInitialized() {
        if (PublicKeyCredentialSource.random == null) {
            PublicKeyCredentialSource.random = new SecureRandom();
        }
    }
}
