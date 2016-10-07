package memlo.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

public class KeyPairFactory {

    static {
        Initializer.init();
    }

    private KeyPairGenerator factory;

    public KeyPairFactory() {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(Algorithm.KEY_PAIR_SPEC.algm);
            this.factory = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm, Algorithm.PROVIDER.algm);
            this.factory.initialize(ecSpec, SecureRandom.getInstance("NativePRNGNonBlocking"));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }

    public KeyPair createKey() {
        return this.factory.generateKeyPair();
    }
}
