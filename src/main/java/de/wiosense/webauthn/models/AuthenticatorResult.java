package de.wiosense.webauthn.models;

import de.wiosense.webauthn.exceptions.VirgilException;

public abstract class AuthenticatorResult {
    public abstract byte[] asCBOR() throws VirgilException;
}
