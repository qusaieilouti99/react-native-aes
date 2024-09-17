package com.tectiv3.aes;

import android.util.Base64;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class RCTAes extends ReactContextBaseJavaModule {

    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String HMAC_SHA_512 = "HmacSHA512";
    final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    private static final String FILE_CIPHER_ALGORITHM = "AES/CBC/NoPadding";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int BLOCK_SIZE = 16;
    private static final int CHUNK_SIZE = BLOCK_SIZE * 4 * 1024;

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static String pbkdf2(String pwd, String salt, Integer cost, Integer length) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(pwd.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), cost);
        byte[] key = ((KeyParameter) gen.generateDerivedParameters(length)).getKey();
        return bytesToHex(key);
    }

    private static String hmacX(String text, String key, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] contentData = text.getBytes(StandardCharsets.UTF_8);
        byte[] akHexData = Hex.decode(key);
        Mac sha_HMAC = Mac.getInstance(algorithm);
        SecretKey secret_key = new SecretKeySpec(akHexData, algorithm);
        sha_HMAC.init(secret_key);
        return bytesToHex(sha_HMAC.doFinal(contentData));
    }

    private static String encrypt(String text, String hexKey, String hexIv) throws Exception {
        if (text == null || text.isEmpty()) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    private static String decrypt(String ciphertext, String hexKey, String hexIv) throws Exception {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static WritableMap doEncryptFile(String hexKey, String hexIv, String hexHmacKey, String inputPath, String outputPath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // convert keys to readable format
        byte[] key = Hex.decode(hexKey);
        byte[] hmacKey = Hex.decode(hexHmacKey);
        byte[] iv = Hex.decode(hexIv);

        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        SecretKey secretHmacKey = new SecretKeySpec(hmacKey, HMAC_SHA_256);
        IvParameterSpec secretIv = new IvParameterSpec(iv);

        // create the HMAC instance which is hmac-sha-256 and
        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(secretHmacKey);

        // create the cipher instance which is aes-cbc-noPadding 256 bit key length
        Cipher cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, secretIv);

        // create the digest instance which is sha-256
        MessageDigest digest = MessageDigest.getInstance("SHA256");

        // prepare the files and streams for the operation
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);


        // some information to properly manage chunks
        long fileSize = inputFile.length();
        byte[] buffer = new byte[CHUNK_SIZE];
        int chunksLength = (int) Math.ceil(((double) fileSize / CHUNK_SIZE));

        // adding the padding manually because we are using no padding mode (aes cbc requires blocks of 16 bytes)
        boolean isMultipleOfBlockSize = fileSize % BLOCK_SIZE == 0;
        long paddingSize = isMultipleOfBlockSize ? 0 : (BLOCK_SIZE - (fileSize % BLOCK_SIZE));


        // start the process
        for (int i = 0; i < chunksLength; i++) {
            // read chunk
            int bytesRead = inputStream.read(buffer);

            // the padding should be appended to last chunk to make the whole file size a multiple of 16
            boolean isLastChunk = i == chunksLength - 1;
            if (isLastChunk && paddingSize > 0) {
                for (int j = bytesRead; j < bytesRead + paddingSize; j++) {
                    buffer[j] = (byte) paddingSize;
                }
                bytesRead += (int) paddingSize; // Adjust bytesRead to include the padding
            }

            // encrypt the chunk
            byte[] output = cipher.update(buffer, 0, bytesRead);

            // sign the encrypted chunk
            mac.update(output);

            // hash the encrypted chunk
            digest.update(output);

            // write the encrypted chunk to the output stream
            outputStream.write(output);
        }

        // get any remaining encrypted padding + might be some bytes of encrypted plain data => with no padding mode this will be empty
        byte[] outputBytes = cipher.doFinal();

        // hash the remaining
        digest.update(outputBytes);

        // sign the remaining
        byte[] hmac = mac.doFinal(outputBytes);

        // hash the signature (HMAC)
        digest.update(hmac);

        // get the auth which is => sha256(encryptedFile + hmac(encryptedFile))
        String auth = bytesToHex(digest.digest());

        outputStream.write(outputBytes);
        outputStream.write(hmac);
        inputStream.close();
        outputStream.close();

        WritableMap result = Arguments.createMap();
        result.putString("auth", auth);
        result.putInt("paddingSize", (int) paddingSize);

        return result;
    }

    public static void doDecryptFile(String hexKey, String hexIv, String hexHmacKey, String theirDigest, String inputPath, String outputPath, int paddingSize) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // validate digest exist
        if (theirDigest == null) {
            throw new IOException("Missing digest!");
        }

        // convert keys to readable format
        byte[] key = Hex.decode(hexKey);
        byte[] hmacKey = Hex.decode(hexHmacKey);
        byte[] iv = Hex.decode(hexIv);

        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        SecretKey secretHmacKey = new SecretKeySpec(hmacKey, HMAC_SHA_256);
        IvParameterSpec secretIv = new IvParameterSpec(iv);

        // create the HMAC instance which is hmac-sha-256 and
        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(secretHmacKey);

        // create the cipher instance which is aes-cbc-noPadding 256 bit key length
        Cipher cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, secretIv);

        // create the digest instance which is sha-256
        MessageDigest digest = MessageDigest.getInstance("SHA256");

        // prepare the files and streams for the operation
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        // validate file size, if less than mac length which is 32 then we can't proceed, because file should contain (encryptedData + hmac) which is +32
        if (inputFile.length() <= mac.getMacLength()) {
            throw new InvalidKeyException("Message shorter than crypto overhead!");
        }

        // the chunk size 64kb
        byte[] buffer = new byte[CHUNK_SIZE];

        // the full size that should be read is fileSize - 32 ( hmac length )
        int remainingData = (int) inputFile.length() - mac.getMacLength();
        while (remainingData > 0) {
            boolean isLastChunk = remainingData <= CHUNK_SIZE;

            // read chunk
            int bytesRead = inputStream.read(buffer, 0, Math.min(buffer.length, remainingData));

            // sign the encrypted data
            mac.update(buffer, 0, bytesRead);

            // hash the encrypted data
            digest.update(buffer, 0, bytesRead);

            // decrypt the encrypted data
            byte[] output = cipher.update(buffer, 0, bytesRead);

            // if last chunk, then remove the possible added padding before writing
            if (output != null) {
                if (isLastChunk) {
                    outputStream.write(removePadding(output, paddingSize));
                } else {
                    outputStream.write(output);
                }
            }

            // recalculate the remaining after each chunk
            remainingData -= bytesRead;
        }

        // finalize the hmac
        byte[] ourMac = mac.doFinal();

        // read their mac from the file (the last 32 bytes)
        byte[] theirMac = new byte[mac.getMacLength()];
        readFully(inputStream, theirMac);

        // validate hmac equality
        if (!MessageDigest.isEqual(ourMac, theirMac)) {
            if (outputFile.exists()) {
                outputFile.delete();
            }
            inputStream.close();
            outputStream.close();
            throw new IOException("MAC doesn't match!");
        }

        // hash the hmac ( we use their mac because our and their is identical )
        byte[] ourDigest = digest.digest(theirMac);

        // validate auth equality with the received auth
        if (!MessageDigest.isEqual(ourDigest, Hex.decode(theirDigest))) {
            if (outputFile.exists()) {
                outputFile.delete();
            }
            inputStream.close();
            outputStream.close();
            throw new IOException("Digest doesn't match!");
        }

        // finalize the remaining decrypted bytes and write them
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }

        inputStream.close();
        outputStream.close();
    }

    public static void readFully(FileInputStream in, byte[] buffer) throws IOException {
        int offset = 0;

        for (; ; ) {
            int read = in.read(buffer, offset, buffer.length - offset);

            if (read + offset < buffer.length) offset += read;
            else return;
        }
    }

    public static byte[] removePadding(byte[] data, int paddingSize) {
        if (paddingSize == 0) {
            return data; // No padding to remove
        }
        int length = data.length - paddingSize;
        byte[] unPaddedData = new byte[length];
        System.arraycopy(data, 0, unPaddedData, 0, length);
        return unPaddedData;
    }

    @NonNull
    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String data, String key, String iv, String algorithm, Promise promise) {
        try {
            String result = encrypt(data, key, iv);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, String iv, String algorithm, Promise promise) {
        try {
            String result = decrypt(data, pwd, iv);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void encryptFile(String pwd, String iv, String hmacKey, String inputFile, String outputFile, Promise promise) {
        try {
            CryptoThread thread = new CryptoThread(pwd, iv, hmacKey, "", inputFile, outputFile, 0, promise, "encrypt");
            thread.start();


        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decryptFile(String pwd, String iv, String hmacKey, String digest, String inputFile, String outputFile, int paddingSize, Promise promise) {
        try {
            CryptoThread thread = new CryptoThread(pwd, iv, hmacKey, digest, inputFile, outputFile, paddingSize, promise, "decrypt");
            thread.start();
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void pbkdf2(String pwd, String salt, Integer cost, Integer length, Promise promise) {
        try {
            String result = pbkdf2(pwd, salt, cost, length);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac256(String data, String pwd, Promise promise) {
        try {
            String result = hmacX(data, pwd, HMAC_SHA_256);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void hmac512(String data, String pwd, Promise promise) {
        try {
            String result = hmacX(data, pwd, HMAC_SHA_512);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha256(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-256");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha1(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-1");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void sha512(String data, Promise promise) {
        try {
            String result = shaX(data, "SHA-512");
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomUuid(Promise promise) {
        try {
            String result = UUID.randomUUID().toString();
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomKey(Integer length, Promise promise) {
        try {
            byte[] key = new byte[length];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(key);
            String keyHex = bytesToHex(key);
            promise.resolve(keyHex);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    private String shaX(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data.getBytes());
        byte[] digest = md.digest();
        return bytesToHex(digest);
    }

    static class CryptoThread extends Thread {

        String key, iv, hmacKey, digest, inputPath, outputPath, mode;
        Promise promise;

        int paddingSize;

        CryptoThread(String key, String iv, String hmacKey, String digest, String inputPath, String outputPath, int paddingSize, Promise promise, String mode) {
            this.key = key;
            this.iv = iv;
            this.hmacKey = hmacKey;
            this.inputPath = inputPath;
            this.outputPath = outputPath;
            this.mode = mode;
            this.promise = promise;
            this.digest = digest;
            this.paddingSize = paddingSize;
        }

        @Override
        public void run() {
            try {
                if (Objects.equals(mode, "encrypt")) {
                    WritableMap result = doEncryptFile(key, iv, hmacKey, inputPath, outputPath);
                    promise.resolve(result);
                } else {
                    doDecryptFile(key, iv, hmacKey, digest, inputPath, outputPath, paddingSize);
                    promise.resolve(true);
                }
            } catch (Exception e) {
                promise.reject("-1", e.getMessage());
                // Code to handle an IOException here
            }

        }

    }
}
