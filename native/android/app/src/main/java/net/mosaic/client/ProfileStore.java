package net.mosaic.client;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class ProfileStore {
    private static SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias("mosaic.configuration")) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder("mosaic.configuration", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
            generator.generateKey();
        }
        return (SecretKey) store.getKey("mosaic.configuration", null);
    }

    static void save(Context context, byte[] profile) throws Exception {
        if (profile.length > 98304 || !Native.validate(profile)) { throw new Exception("Invalid configuration"); }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] encrypted = cipher.doFinal(profile);
        byte[] result = new byte[12 + encrypted.length];
        System.arraycopy(cipher.getIV(), 0, result, 0, 12);
        System.arraycopy(encrypted, 0, result, 12, encrypted.length);
        File temporary = new File(context.getFilesDir(), "configuration.new");
        try (java.io.FileOutputStream output = context.openFileOutput(temporary.getName(), Context.MODE_PRIVATE)) {
            output.write(result);
            output.getFD().sync();
        }
        Files.move(temporary.toPath(), new File(context.getFilesDir(), "configuration").toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    static byte[] load(Context context) throws Exception {
        File file = new File(context.getFilesDir(), "configuration");
        if (file.length() < 28 || file.length() > 98432) { throw new Exception("Invalid stored configuration"); }
        byte[] bytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Arrays.copyOf(bytes, 12)));
        return cipher.doFinal(bytes, 12, bytes.length - 12);
    }
}
