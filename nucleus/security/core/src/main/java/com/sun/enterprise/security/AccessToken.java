package com.sun.enterprise.security;

import com.sun.enterprise.security.auth.login.common.PasswordCredential;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import java.io.*;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AccessToken implements Serializable {

    private static Logger _logger = null;

    static {
        _logger = SecurityLoggerInfo.getLogger();
    }

    private static final long serialVersionUID = 7053910780650780103L;

    private static final byte[] salt = {
            (byte) 0x12, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
    };


    private final String username;
    private final char[] password;
    private final String realmName;

    private AccessToken(String username, char[] password, String realmName) {
        this.username = username;
        this.password = password;
        this.realmName = realmName;
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        return password;
    }

    public String getRealmName() {
        return realmName;
    }

    public static Optional<byte[]> getAccessToken(byte[] keyBytes) {
        if (keyBytes == null) {
            return Optional.empty();
        }

        SecurityContext securityContext = SecurityContext.getCurrent();
        if (securityContext == null) {
            return Optional.empty();
        }

        Subject subject = securityContext.getSubject();
        if (subject == null) {
            return Optional.empty();
        }

        Set<Object> privateCredentials = subject.getPrivateCredentials();
        if (privateCredentials == null) {
            return Optional.empty();
        }

        for (Object o : privateCredentials) {
            if (o instanceof PasswordCredential) {
                PasswordCredential pc = (PasswordCredential) o;
                AccessToken token = new AccessToken(pc.getUser(), pc.getPassword(), pc.getRealm());
                return token.encode(keyBytes);
            }
        }
        return Optional.empty();
    }

    private Optional<byte[]> encode(byte[] keyBytes) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(this);
            out.flush();
            byte[] accessTokenBytes = bos.toByteArray();

            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(accessTokenBytes);
            return Optional.of(encryptedBytes);
        } catch (Exception e) {
            _logger.log(Level.INFO, "encode token failed.", e);
        }
        return Optional.empty();
    }

    public static Optional<AccessToken> decode(byte[] keyBytes, byte[] data) {
        try {
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(data);

            ByteArrayInputStream bi = new ByteArrayInputStream(decryptedBytes);
            ObjectInputStream ois = new ObjectInputStream(bi);

            AccessToken accessToken = (AccessToken) ois.readObject();
            return Optional.of(accessToken);
        } catch (Exception e) {
            _logger.log(Level.INFO, "decode token failed.", e);
        }
        return Optional.empty();
    }

    public static byte[] generateKeyBytes(String keyString) throws Exception {
        char[] key = keyString.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(key, salt, 65536, 256); // 65536 iterations, 256-bit key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}