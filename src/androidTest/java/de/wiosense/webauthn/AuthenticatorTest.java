package de.wiosense.webauthn;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import androidx.fragment.app.FragmentActivity;
import androidx.test.InstrumentationRegistry;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.List;

import androidx.test.runner.AndroidJUnit4;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import de.wiosense.webauthn.models.AttestationObject;
import de.wiosense.webauthn.models.GetAssertionOptions;
import de.wiosense.webauthn.models.GetAssertionResult;
import de.wiosense.webauthn.models.MakeCredentialOptions;
import de.wiosense.webauthn.models.PublicKeyCredentialDescriptor;
import de.wiosense.webauthn.models.PublicKeyCredentialSource;
import de.wiosense.webauthn.exceptions.VirgilException;
import de.wiosense.webauthn.exceptions.CtapException;
import de.wiosense.webauthn.util.CredentialSafe;
import de.wiosense.webauthn.util.WebAuthnCryptography;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class AuthenticatorTest {
    private Authenticator authenticator;
    private CredentialSafe credentialSafe;
    private WebAuthnCryptography cryptography;
    private FragmentActivity activity;
    private static final String TAG = "AuthenticatorTest";

    public static final String MAKE_CREDENTIAL_JSON = "{\n" +
            "    \"authenticatorExtensions\": [],\n" + // optional and currently ignored
            "    \"clientDataHash\": \"LTCT/hWLtJenIgi0oUhkJz7dE8ng+pej+i6YI1QQu60=\",\n" + // base64
            "    \"credTypesAndPubKeyAlgs\": [\n" +
            "        [\"public-key\", -7]\n" +
            "    ],\n" +
            "    \"excludeCredentials\": [\n" +
            "        {\n" +
            "            \"type\": \"public-key\",\n" +
            "            \"id\": \"lVGyXHwz6vdYignKyctbkIkJto/ADbYbHhE7+ss/87o=\",\n" + // base64
            "            \"transports\": [\"USB\", \"NFC\"]\n" + // member optional but ignored
            "        }\n" +
            "    ],\n" +
            "    \"requireResidentKey\": true,\n" +
            "    \"requireUserPresence\": true,\n" +
            "    \"requireUserVerification\": false,\n" +
            "    \"rp\": {\n" +
            "        \"name\": \"demo.wiokey.de\",\n" +
            "        \"id\": \"demo.wiokey.de\"\n" +
            "    },\n" +
            "    \"user\": {\n" +
            "        \"name\": \"testuser\",\n" +
            "        \"displayName\": \"Test User\",\n" +
            "        \"id\": \"/QIAAAAAAAAAAA==\"\n" + // base64
            "    }\n" +
            "}";

    public static final String GET_ASSERTION_JSON = "{\n" +
            "    \"allowCredentialDescriptorList\": [{\n" +
            "        \"id\": \"jVtTOKLHRMN17I66w48XWuJadCitXg0xZKaZvHdtW6RDCJhxO6Cfff9qbYnZiMQ1pl8CzPkXcXEHwpQYFknN2w==\",\n" + // base64
            "        \"type\": \"public-key\"\n" +
            "    }],\n" +
            "    \"authenticatorExtensions\": \"\",\n" +  // optional and ignored
            "    \"clientDataHash\": \"BWlg/oAqeIhMHkGAo10C3sf4U/sy0IohfKB0OlcfHHU=\",\n" + // base64
            "    \"requireUserPresence\": true,\n" +
            "    \"requireUserVerification\": false,\n" +
            "    \"rpId\": \"demo.wiokey.de\"\n" +
            "}";

    @Before
    public void setUp() throws Exception {
        Context ctx = InstrumentationRegistry.getContext();
        boolean hasStrongbox = ctx.getPackageManager()
                .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        this.authenticator = new Authenticator(ctx,  hasStrongbox);
        this.credentialSafe = this.authenticator.credentialSafe;
        this.cryptography = this.authenticator.cryptoProvider;
        this.activity = new FragmentActivity();
        Log.d(TAG, "MAKE_CREDENTIAL_JSON = \n" + MAKE_CREDENTIAL_JSON);
        Log.d(TAG, "GET_ASSERTION_JSON = \n" + GET_ASSERTION_JSON);
    }

    /**
     * Ensure that we can decode some JSON and create a credential.
     *
     * @throws VirgilException
     * @throws CtapException
     */
    @Test
    public void fromJson() throws VirgilException, CtapException {
        MakeCredentialOptions options = MakeCredentialOptions.fromJSON(MAKE_CREDENTIAL_JSON);
        AttestationObject attObj = authenticator.makeCredential(options, this.activity);
    }

    /**
     * Go through the whole dance of creating a new credential and generating an assertion
     * from the credential. Ensure that the signature is valid.
     * @throws VirgilException
     * @throws CtapException
     * @throws CborException
     */
    @Test
    public void makeCredentialAndGetAssertionWithAllowCredential()
            throws VirgilException, CtapException, CborException {
        MakeCredentialOptions makeCredentialOptions = MakeCredentialOptions.fromJSON(MAKE_CREDENTIAL_JSON);
        AttestationObject attObj = authenticator.makeCredential(makeCredentialOptions, this.activity);
        byte[] cborEncoded = attObj.asCBOR();

        ByteArrayInputStream bais = new ByteArrayInputStream(cborEncoded);
        Map decoded = (Map) new CborDecoder(bais).decode().get(0);
        String fmt = ((UnicodeString) decoded.get(new UnicodeString("fmt"))).getString();
        assertEquals(fmt, "none");

        byte[] credentialId = attObj.getCredentialId();

        // Now let's see if we can generate an assertion based on the returned credential ID
        GetAssertionOptions getAssertionOptions = GetAssertionOptions.fromJSON(GET_ASSERTION_JSON);
        //getAssertionOptions.allowCredentialDescriptorList.clear();
        getAssertionOptions.allowCredentialDescriptorList.add(new PublicKeyCredentialDescriptor("public-key", credentialId, null));

        GetAssertionResult getAssertionResult = authenticator.getAssertion(getAssertionOptions, credentialList -> credentialList.get(0), this.activity);

        ByteBuffer resultBuf = ByteBuffer.allocate(getAssertionOptions.clientDataHash.length + getAssertionResult.authenticatorData.length);
        resultBuf.put(getAssertionResult.authenticatorData);
        resultBuf.put(getAssertionOptions.clientDataHash);
        byte[] signedData = resultBuf.array();
        List<PublicKeyCredentialSource> sources = this.credentialSafe.getKeysForEntity(makeCredentialOptions.rpEntity.id);
        PublicKeyCredentialSource source = sources.get(sources.size() - 1);
        KeyPair keyPair = this.credentialSafe.getKeyPairByAlias(source.keyPairAlias);
        assertTrue(this.cryptography.verifySignature(keyPair.getPublic(), signedData, getAssertionResult.signature));
    }

    /**
     * Ensure that we fail to create a credential if user verification is requested, but we didn't
     * initialize the Authenticator with biometric auth set to true.
     * @throws VirgilException
     */
    @Test
    public void testFailureOnVerificationRequiredWithoutSupport() throws VirgilException {
        MakeCredentialOptions makeCredentialOptions = MakeCredentialOptions.fromJSON(MAKE_CREDENTIAL_JSON);
        makeCredentialOptions.requireUserVerification = true;
        makeCredentialOptions.requireUserPresence = false;

        try {
            AttestationObject attObj = authenticator.makeCredential(makeCredentialOptions, this.activity);
            Assert.fail("makeCredential should have failed without biometric support");
        } catch (CtapException e) {
            // success! any other exception is a failure
        }
    }

    /**
     * Ensure that the "exclude credentials" functionality keeps us from creating a new credential
     * when an excluded credential is known.
     * @throws VirgilException
     * @throws CtapException
     */
    @Test
    public void testExcludeCredentials() throws VirgilException, CtapException {
        MakeCredentialOptions makeCredentialOptions = MakeCredentialOptions.fromJSON(MAKE_CREDENTIAL_JSON);
        AttestationObject firstAttestationObject = authenticator.makeCredential(makeCredentialOptions, this.activity);

        // Now we want to pull out the ID of the just-created credential, add it to the exclude list,
        // and ensure that we see a failure when creating a second credential.

        makeCredentialOptions.excludeCredentialDescriptorList.add(new PublicKeyCredentialDescriptor("public-key", firstAttestationObject.getCredentialId(), null));
        try {
            AttestationObject secondAttestationObject = authenticator.makeCredential(makeCredentialOptions, this.activity);
            Assert.fail("makeCredential should have failed due to a matching credential ID in the exclude list");
        } catch (CtapException e) {
            // good! the matching credential descriptor caused the authenticator to reject the request
        }
    }


    /**
     * Make sure that we can pass an empty allowed credentials list.
     * @throws VirgilException
     * @throws CtapException
     */
    @Test
    public void testAllowCredentialsEmpty() throws VirgilException, CtapException {
        MakeCredentialOptions makeCredentialOptions = MakeCredentialOptions.fromJSON(MAKE_CREDENTIAL_JSON);
        AttestationObject attObj = authenticator.makeCredential(makeCredentialOptions, this.activity);

        GetAssertionOptions getAssertionOptions = GetAssertionOptions.fromJSON(GET_ASSERTION_JSON);
        getAssertionOptions.allowCredentialDescriptorList.clear();
        authenticator.getAssertion(getAssertionOptions, credentialList -> credentialList.get(0), this.activity);
    }
}