package memlo.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyPairFactory {

    private KeyPairGenerator factory;

    public KeyPairFactory() {
        try {
            this.factory = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm);
            this.factory.initialize(112, SecureRandom.getInstance("NativePRNGNonBlocking"));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPair createKey() {
        return this.factory.generateKeyPair();
    }
}
