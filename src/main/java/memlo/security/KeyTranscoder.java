package memlo.security;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * Encodes/Decodes keys
 */
public final class KeyTranscoder {
    private static final SecretKeyFactory secretKeyFactory;
    private static final KeyFactory keyPairFactory;

    static {
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(Algorithm.SECRET_KEY.algm);
            keyPairFactory = KeyFactory.getInstance(Algorithm.KEY_PAIR.algm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getSpec(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    public static String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static SecretKey decodeSecretKey(String encodedSecret) {
        try {
            return secretKeyFactory.generateSecret(new DESedeKeySpec(getSpec(encodedSecret)));
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
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
