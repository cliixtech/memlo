package memlo.security;

import static memlo.security.EncodingUtils.asBytes;
import static memlo.security.EncodingUtils.asString;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encodes/Decodes keys
 */
public final class KeyTranscoder {
    private static final SecretKeyFactory secretKeyFactory;
    private static final KeyFactory keyPairFactory;

    static {
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(Algorithm.SECRET_KEY.algm, Algorithm.PROVIDER.algm);
            keyPairFactory = KeyFactory.getInstance(Algorithm.KEY_PAIR.algm, Algorithm.PROVIDER.algm);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getSpec(String encoded) {
        return asBytes(encoded);
    }

    public static String encodeKey(Key key) {
        return asString(key.getEncoded());
    }

    public static SecretKey encodeSecretKey(byte[] plainSecret) {
        try {
            return secretKeyFactory.generateSecret(new SecretKeySpec(plainSecret, Algorithm.SECRET_KEY.algm));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey decodeSecretKey(String encodedSecret) {
        return encodeSecretKey(getSpec(encodedSecret));
    }

    public static PublicKey decodePublicKey(String encodedKey) {
        try {
            KeySpec pubKeySpec = new X509EncodedKeySpec(getSpec(encodedKey));
            return keyPairFactory.generatePublic(pubKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey decodePrivateKey(String encodedKey) {
        try {
            KeySpec privateKeySpec = new PKCS8EncodedKeySpec(getSpec(encodedKey));
            return keyPairFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
