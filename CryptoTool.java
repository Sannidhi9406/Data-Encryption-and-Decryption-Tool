package project2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Data Encryption and Decryption Tool
 * -----------------------------------
 * AES-256-GCM (password based) and RSA-2048 (hybrid: RSA-OAEP wraps a random AES key).
 *
 * Run (Java 11+ can run the source file directly):
 *   java CryptoTool.java genkeys --name mykey
 *   java CryptoTool.java encrypt --algo aes --text "hello" --password secret
 *   java CryptoTool.java decrypt --algo aes --text <base64> --password secret
 *   java CryptoTool.java encrypt --algo rsa --in a.pdf --out a.enc --key mykey_public.pem
 *   java CryptoTool.java decrypt --algo rsa --in a.enc --out a.pdf --key mykey_private.pem
 *   java CryptoTool.java compare
 */
public class CryptoTool {

    static final byte[] AES_MAGIC = "AESG".getBytes(StandardCharsets.US_ASCII);
    static final byte[] RSA_MAGIC = "RSAH".getBytes(StandardCharsets.US_ASCII);
    static final SecureRandom RNG = new SecureRandom();
    static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // ---------------------------- AES (symmetric) ----------------------------
    /** Turn a password into a 256-bit key using PBKDF2 (deliberately slow). */
    static SecretKey deriveKey(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 200_000, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    static byte[] gcm(int mode, SecretKey key, byte[] nonce, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, key, new GCMParameterSpec(128, nonce));
        return c.doFinal(data);
    }

    static byte[] aesEncrypt(byte[] data, String password) throws GeneralSecurityException {
        byte[] salt = new byte[16], nonce = new byte[12];
        RNG.nextBytes(salt);
        RNG.nextBytes(nonce);
        byte[] ct = gcm(Cipher.ENCRYPT_MODE, deriveKey(password, salt), nonce, data);
        return concat(AES_MAGIC, salt, nonce, ct);
    }

    static byte[] aesDecrypt(byte[] blob, String password) throws GeneralSecurityException {
        if (blob.length < 32 || !Arrays.equals(Arrays.copyOfRange(blob, 0, 4), AES_MAGIC))
            throw new GeneralSecurityException("Not an AES-encrypted blob from this tool.");
        byte[] salt = Arrays.copyOfRange(blob, 4, 20);
        byte[] nonce = Arrays.copyOfRange(blob, 20, 32);
        byte[] ct = Arrays.copyOfRange(blob, 32, blob.length);
        return gcm(Cipher.DECRYPT_MODE, deriveKey(password, salt), nonce, ct);
    }

    // ---------------------------- RSA (hybrid) ----------------------------
    static void generateKeys(String name, int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits);
        KeyPair kp = kpg.generateKeyPair();
        Files.writeString(Paths.get(name + "_private.pem"), toPem("PRIVATE KEY", kp.getPrivate().getEncoded()));
        Files.writeString(Paths.get(name + "_public.pem"), toPem("PUBLIC KEY", kp.getPublic().getEncoded()));
        System.out.println("Created " + name + "_private.pem (keep secret!) and " + name + "_public.pem");
    }

    /** RSA can only encrypt ~190 bytes, so a random AES key encrypts the data and RSA-OAEP wraps that key. */
    static byte[] rsaEncrypt(byte[] data, String pubPath) throws Exception {
        PublicKey pub = loadPublic(pubPath);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, pub, OAEP);
        byte[] wrapped = rsa.doFinal(aesKey.getEncoded());

        byte[] ct = gcm(Cipher.ENCRYPT_MODE, aesKey, nonce, data);
        byte[] len = ByteBuffer.allocate(2).putShort((short) wrapped.length).array();
        return concat(RSA_MAGIC, len, wrapped, nonce, ct);
    }

    static byte[] rsaDecrypt(byte[] blob, String privPath) throws Exception {
        if (blob.length < 6 || !Arrays.equals(Arrays.copyOfRange(blob, 0, 4), RSA_MAGIC))
            throw new GeneralSecurityException("Not an RSA-encrypted blob from this tool.");
        int n = ByteBuffer.wrap(blob, 4, 2).getShort() & 0xFFFF;
        byte[] wrapped = Arrays.copyOfRange(blob, 6, 6 + n);
        byte[] nonce = Arrays.copyOfRange(blob, 6 + n, 18 + n);
        byte[] ct = Arrays.copyOfRange(blob, 18 + n, blob.length);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, loadPrivate(privPath), OAEP);
        SecretKey aesKey = new SecretKeySpec(rsa.doFinal(wrapped), "AES");
        return gcm(Cipher.DECRYPT_MODE, aesKey, nonce, ct);
    }

    // ---------------------------- Comparison ----------------------------
    static void compare() throws Exception {
        System.out.println("Benchmarking (this takes a few seconds)...\n");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        long t = System.nanoTime();
        KeyPair kp = kpg.generateKeyPair();
        double rsaKeygen = (System.nanoTime() - t) / 1e6;

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        t = System.nanoTime();
        kg.generateKey();
        double aesKeygen = (System.nanoTime() - t) / 1e6;

        System.out.printf("Key generation:  AES-256 %.3f ms   |   RSA-2048 %.1f ms%n%n", aesKeygen, rsaKeygen);
        System.out.printf("%8s | %9s %9s | %9s %9s | RSA is slower by%n", "Size", "AES enc", "AES dec", "RSA enc", "RSA dec");
        System.out.println("-".repeat(74));

        Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsaEnc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), OAEP);
        Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsaDec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), OAEP);
        final int chunk = 190; // max plaintext per RSA-2048 OAEP-SHA256 block

        // warm-up so JIT compilation doesn't distort the first row
        byte[] warm = new byte[1000];
        SecretKey wk = kg.generateKey();
        byte[] wn = new byte[12];
        for (int i = 0; i < 200; i++) gcm(Cipher.DECRYPT_MODE, wk, wn, gcm(Cipher.ENCRYPT_MODE, wk, wn, warm));

        for (int size : new int[]{1_000, 10_000, 100_000}) {
            byte[] data = new byte[size];
            RNG.nextBytes(data);
            SecretKey key = kg.generateKey();
            byte[] nonce = new byte[12];
            RNG.nextBytes(nonce);

            t = System.nanoTime();
            byte[] ct = gcm(Cipher.ENCRYPT_MODE, key, nonce, data);
            double aE = (System.nanoTime() - t) / 1e6;
            t = System.nanoTime();
            gcm(Cipher.DECRYPT_MODE, key, nonce, ct);
            double aD = (System.nanoTime() - t) / 1e6;

            int blocks = (size + chunk - 1) / chunk;
            byte[][] enc = new byte[blocks][];
            t = System.nanoTime();
            for (int i = 0; i < blocks; i++)
                enc[i] = rsaEnc.doFinal(data, i * chunk, Math.min(chunk, size - i * chunk));
            double rE = (System.nanoTime() - t) / 1e6;
            t = System.nanoTime();
            for (byte[] b : enc) rsaDec.doFinal(b);
            double rD = (System.nanoTime() - t) / 1e6;

            System.out.printf("%7dB | %7.3fms %7.3fms | %7.1fms %7.1fms | ~%,.0fx%n",
                    size, aE, aD, rE, rD, (rE + rD) / (aE + aD));
        }

        System.out.println("\nSecurity & design summary\n-------------------------");
        System.out.println("                  AES-256-GCM                    RSA-2048 (OAEP)");
        System.out.println("Type              Symmetric (one shared key)     Asymmetric (public/private pair)");
        System.out.println("Speed             Very fast (hardware support)   Very slow, tiny message limit");
        System.out.println("Data limit        Practically unlimited          ~190 bytes per operation");
        System.out.println("Key distribution  Hard (must share secret)       Easy (publish public key)");
        System.out.println("Integrity         Built in (GCM auth tag)        None by itself");
        System.out.println("Security level    ~256-bit                       ~112-bit (2048-bit key)");
        System.out.println("\nTakeaway: use RSA to exchange/wrap a key, use AES to encrypt the data.");
        System.out.println("That is exactly what this tool's 'rsa' mode does (hybrid encryption).");
    }

    // ---------------------------- Helpers ----------------------------
    static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    static String toPem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    static byte[] fromPem(String path) throws IOException {
        String pem = Files.readString(Paths.get(path)).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(pem);
    }

    static PublicKey loadPublic(String path) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(fromPem(path)));
    }

    static PrivateKey loadPrivate(String path) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fromPem(path)));
    }

    static final java.util.Scanner IN = new java.util.Scanner(System.in);

    static String ask(String prompt) {
        System.out.print(prompt);
        if (!IN.hasNextLine()) { System.out.println(); System.exit(0); }
        return IN.nextLine().trim();
    }

    static String readPassword() {
        if (System.console() != null) return new String(System.console().readPassword("Password: "));
        return ask("Password: ");
    }

    static void die(String msg) {
        System.err.println(msg);
        System.exit(1);
    }

    // ---------------------------- Interactive menu ----------------------------
    static void menu() {
        while (true) {
            System.out.println("\n=== Data Encryption and Decryption Tool ===");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Generate RSA key pair");
            System.out.println("4. Compare AES vs RSA");
            System.out.println("0. Exit");
            String choice = ask("Choose: ");
            try {
                switch (choice) {
                    case "1": menuCrypt(true); break;
                    case "2": menuCrypt(false); break;
                    case "3":
                        String name = ask("Key name (e.g. mykey): ");
                        generateKeys(name.isEmpty() ? "key" : name, 2048);
                        break;
                    case "4": compare(); break;
                    case "0": System.out.println("Bye!"); return;
                    default: System.out.println("Invalid choice, try again.");
                }
            } catch (GeneralSecurityException e) {
                System.out.println("Failed: wrong key/password, or data was tampered with.");
            } catch (Exception e) {
                System.out.println("Error: " + e);
            }
        }
    }

    static void menuCrypt(boolean enc) throws Exception {
        String verb = enc ? "Encrypt" : "Decrypt";
        boolean aes = ask("Algorithm - 1) AES (password)  2) RSA (key files): ").equals("1");
        boolean text = ask("Input - 1) Text message  2) File: ").equals("1");

        byte[] data;
        String inPath = null;
        if (text) {
            String msg = ask(enc ? "Enter message: " : "Paste Base64 ciphertext: ");
            data = enc ? msg.getBytes(StandardCharsets.UTF_8) : Base64.getDecoder().decode(msg);
        } else {
            inPath = ask("Input file path: ");
            data = Files.readAllBytes(Paths.get(inPath));
        }

        byte[] result;
        if (aes) {
            String pw = readPassword();
            result = enc ? aesEncrypt(data, pw) : aesDecrypt(data, pw);
        } else {
            String key = ask(enc ? "Public key file (e.g. mykey_public.pem): "
                                 : "Private key file (e.g. mykey_private.pem): ");
            result = enc ? rsaEncrypt(data, key) : rsaDecrypt(data, key);
        }

        if (text) {
            System.out.println("\n" + verb + "ed result:");
            System.out.println(enc ? Base64.getEncoder().encodeToString(result)
                                   : new String(result, StandardCharsets.UTF_8));
        } else {
            String out = ask("Output file path: ");
            Files.write(Paths.get(out), result);
            System.out.println("Saved to " + out);
        }
    }

    // ---------------------------- CLI ----------------------------
    public static void main(String[] args) throws Exception {
        if (args.length == 0) { menu(); return; }
        String cmd = args[0];
        Map<String, String> opt = new HashMap<>();
        for (int i = 1; i + 1 < args.length; i += 2) opt.put(args[i].replaceFirst("^--", ""), args[i + 1]);

        if (cmd.equals("genkeys")) {
            generateKeys(opt.getOrDefault("name", "key"), Integer.parseInt(opt.getOrDefault("bits", "2048")));
            return;
        }
        if (cmd.equals("compare")) {
            compare();
            return;
        }
        if (!cmd.equals("encrypt") && !cmd.equals("decrypt")) die("Unknown command: " + cmd);

        boolean enc = cmd.equals("encrypt");
        String algo = opt.get("algo");
        if (algo == null || !(algo.equals("aes") || algo.equals("rsa"))) die("Provide --algo aes|rsa");

        byte[] data;
        if (opt.containsKey("text"))
            data = enc ? opt.get("text").getBytes(StandardCharsets.UTF_8) : Base64.getDecoder().decode(opt.get("text"));
        else if (opt.containsKey("in")) data = Files.readAllBytes(Paths.get(opt.get("in")));
        else { die("Provide --text or --in"); return; }

        byte[] result = null;
        try {
            if (algo.equals("aes")) {
                String pw = opt.containsKey("password") ? opt.get("password") : readPassword();
                result = enc ? aesEncrypt(data, pw) : aesDecrypt(data, pw);
            } else {
                if (!opt.containsKey("key")) die("RSA needs --key");
                result = enc ? rsaEncrypt(data, opt.get("key")) : rsaDecrypt(data, opt.get("key"));
            }
        } catch (GeneralSecurityException e) {
            die("Failed: wrong key/password, or data was tampered with.");
        }

        if (opt.containsKey("out")) {
            Files.write(Paths.get(opt.get("out")), result);
            System.out.println("Saved to " + opt.get("out"));
        } else if (opt.containsKey("text")) {
            System.out.println(enc ? Base64.getEncoder().encodeToString(result)
                                   : new String(result, StandardCharsets.UTF_8));
        } else die("Provide --out for file operations");
    }
}