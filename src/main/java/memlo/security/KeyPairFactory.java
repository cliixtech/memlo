package memlo.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyPairFactory {

    private KeyPairGenerator factory;

    public KeyPairFactory() {
        try {
            this.factory = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(Algorithm.KEY_PAIR_SPEC.algm);
            this.factory.initialize(ecSpec, SecureRandom.getInstance("NativePRNGNonBlocking"));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

    }

    public KeyPair createKey() {
        return this.factory.generateKeyPair();
    }
}
