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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(AndroidJUnit4.class)
public class CredentialSafeTest {
    private CredentialSafe credentialSafe;
    private static final String TAG = "CredentialSafeTest";

    @Before
    public void setUp() throws Exception {
        Context ctx = InstrumentationRegistry.getContext();
        boolean hasStrongbox = ctx.getPackageManager()
                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        Log.d(TAG, "Test medium hasStrongbox = " + hasStrongbox);
        this.credentialSafe = new CredentialSafe(ctx, hasStrongbox);
    }

    @Test
    public void generateCredential() throws VirgilException {
        PublicKeyCredentialSource cs = this.credentialSafe.generateCredential(
                "myentity",
                null,
                "myname"
        );
        assertEquals(cs.rpId, "myentity");
    }

    @Test
    public void getKeyPairByAlias() throws VirgilException {
        PublicKeyCredentialSource cs = this.credentialSafe.generateCredential(
                "myentity",
                null,
                "myname"
        );
        KeyPair keyPair = this.credentialSafe.getKeyPairByAlias(cs.keyPairAlias);

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }
}