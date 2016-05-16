package memlo.security;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signer {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

    private static final Signer INSTANCE = new Signer();

    private Signer() {

    }

    public static Signer getInstance() {
        return INSTANCE;
    }

    public String sign(PrivateKey privateKey, String... data) {
        try {
            Signature signer = Signature.getInstance(Algorithm.KEY_PAIR_SIGN.algm);
            signer.initSign(privateKey);
            for (String d: data) {
                signer.update(d.getBytes(UTF_8));
            }
            byte[] signature = signer.sign();
            return Base64.getEncoder().encodeToString(signature);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(PublicKey publicKey, String signature, String... data) {
        try {
            Signature signer = Signature.getInstance(Algorithm.KEY_PAIR_SIGN.algm);
            signer.initVerify(publicKey);
            for (String d: data) {
                signer.update(d.getBytes(UTF_8));
            }
            byte[] rawSignature = Base64.getDecoder().decode(signature);
            return signer.verify(rawSignature);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }
    }

    public String hmac(String key, String... data) {
        try {
            Mac generator = Mac.getInstance(Algorithm.HMAC.algm);
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(UTF_8), Algorithm.HMAC.algm);
            generator.init(secret);
            for (String d: data) {
                generator.update(d.getBytes(UTF_8));
            }
            byte[] hmac = generator.doFinal();
            return Base64.getEncoder().encodeToString(hmac);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public String digest(String... data) {
        try {
            MessageDigest md = MessageDigest.getInstance(Algorithm.DIGEST.algm);
            for (String d: data) {
                md.update(d.getBytes(UTF_8));
            }
            byte[] bytes = md.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b: bytes) {
                sb.append(String.format("%02X", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}