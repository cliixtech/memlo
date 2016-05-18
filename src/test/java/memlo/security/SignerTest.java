package memlo.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

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
        KeyPair pair = new KeyPairFactory().createKey();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");
        assertThat(signer.verify(pair.getPublic(), signed, "hello", "world")).isTrue();
    }

    @Test
    public void assymetricSign_signAndVerify_wrongKeyFails() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair pair = new KeyPairFactory().createKey();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");

        assertThat(signer.verify(new KeyPairFactory().createKey().getPublic(), signed, "hello", "world")).isFalse();
    }

    @Test
    public void assymetricSign_signAndVerify_wrongContentFails() throws NoSuchAlgorithmException {
        KeyPair pair = new KeyPairFactory().createKey();

        String signed = signer.sign(pair.getPrivate(), "hello", "world");

        assertThat(signer.verify(pair.getPublic(), signed, "hello", "nurse")).isFalse();
    }
}
