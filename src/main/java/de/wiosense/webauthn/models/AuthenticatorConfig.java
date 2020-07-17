package de.wiosense.webauthn.models;

import android.util.Base64;

public class AuthenticatorConfig {
    public static final byte[] AAGUID = Base64.decode(
            "AAAAAAAAAAAAAAAAAAAAAA==",
            Base64.DEFAULT);
}
