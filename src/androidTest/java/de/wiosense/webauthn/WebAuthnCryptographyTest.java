package de.wiosense.webauthn;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyPair;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;
import de.wiosense.webauthn.exceptions.VirgilException;
import de.wiosense.webauthn.models.PublicKeyCredentialSource;
import de.wiosense.webauthn.util.CredentialSafe;
import de.wiosense.webauthn.util.WebAuthnCryptography;

import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class WebAuthnCryptographyTest {
    private CredentialSafe credentialSafe;
    private WebAuthnCryptography crypto;
    private static final String TAG = "WebAuthnCryptographyTest";

    @Before
    public void setUp() throws Exception {
        Context ctx = InstrumentationRegistry.getContext();
        boolean hasStrongbox = ctx.getPackageManager()
                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        Log.d(TAG, "Test medium hasStrongbox = " + hasStrongbox);
        this.credentialSafe = new CredentialSafe(ctx, hasStrongbox);
        this.crypto = new WebAuthnCryptography(this.credentialSafe);
    }

    @Test
    public void verifySignature() throws VirgilException {
        byte[] toSign = "sign me plz".getBytes();
        PublicKeyCredentialSource credentialSource = this.credentialSafe.generateCredential(
                "mine",
                null,
                "myname"
        );
        KeyPair keyPair = this.credentialSafe.getKeyPairByAlias(credentialSource.keyPairAlias);
        byte[] signature = this.crypto.performSignature(keyPair.getPrivate(), toSign, null);
        boolean res = this.crypto.verifySignature(keyPair.getPublic(), toSign, signature);
        assertTrue(res);
    }
}