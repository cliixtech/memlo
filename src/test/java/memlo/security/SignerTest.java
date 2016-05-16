package memlo.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class SignerTest {

    private Signer signer = Signer.getInstance();

    @Test
    public void symetricSign_sameInput_returnSameValue() throws NoSuchAlgorithmException {
        String key = "key";
        String signed1 = signer.hmac(key, "hello", "world");
        String signed2 = signer.hmac(key, "hello", "world");
        assertThat(signed1).isEqualTo(signed2);
    }

    @Test
    public void symetricSign_differentInput_returnSameValue() throws NoSuchAlgorithmException {
        String key = "key";
        String signed1 = signer.hmac(key, "hello", "world");
        String signed2 = signer.hmac(key, "hello", "nurse");
        assertThat(signed1).isNotEqualTo(signed2);
    }

    @Test
    public void assymetricSign_signAndVerify_ok() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm);
        KeyPair pair = generator.generateKeyPair();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");
        assertThat(signer.verify(pair.getPublic(), signed, "hello", "world")).isTrue();
    }

    @Test
    public void assymetricSign_signAndVerify_wrongKeyFails() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm);
        KeyPair pair = generator.generateKeyPair();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");

        assertThat(signer.verify(generator.generateKeyPair().getPublic(), signed, "hello", "world")).isFalse();
    }

    @Test
    public void assymetricSign_signAndVerify_wrongContentFails() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(Algorithm.KEY_PAIR.algm);
        KeyPair pair = generator.generateKeyPair();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");

        assertThat(signer.verify(pair.getPublic(), signed, "hello", "nurse")).isFalse();
    }
}
