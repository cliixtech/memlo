package memlo.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class KeyPairFactory {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPairGenerator factory;

    public KeyPairFactory() {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(Algorithm.KEY_PAIR_SPEC.algm);
            this.factory = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm, Algorithm.KEY_PAIR_PROVIDER.algm);
            this.factory.initialize(ecSpec, SecureRandom.getInstance("NativePRNGNonBlocking"));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            ;
        } catch (InvalidAlgorithmParameterException e) {
            ;
        }

    }

    public KeyPair createKey() {
        return this.factory.generateKeyPair();
    }
}
