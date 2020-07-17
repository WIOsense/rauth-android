package de.wiosense.webauthn.util;

import java.util.List;

import de.wiosense.webauthn.models.PublicKeyCredentialSource;

public interface CredentialSelector {
    PublicKeyCredentialSource selectFrom(List<PublicKeyCredentialSource> credentialList);
}
