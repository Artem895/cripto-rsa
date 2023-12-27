import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Sign {

    private BigInteger n, d, e;

    public void generateKeys() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random);
        BigInteger q = BigInteger.probablePrime(1024, random);

        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        e = new BigInteger("65537");
        d = e.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(d, n);
    }

    public BigInteger signFile(String filePath) throws IOException {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        BigInteger hash = hash(fileBytes);
        BigInteger signature = encrypt(hash);
        return signature;
    }

    public boolean verifySignatureOfFile(String filePath, BigInteger signature) throws IOException {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        BigInteger decryptedSignature = decrypt(signature);
        BigInteger hash = hash(fileBytes);
        return decryptedSignature.equals(hash);
    }

    private BigInteger hash(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input);
            return new BigInteger(1, hashBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        try {
            Sign rsa = new Sign();
            rsa.generateKeys();

            String originalText = new String(Files.readAllBytes(Paths.get("src/main/resources/input2.txt")), StandardCharsets.UTF_8);

            BigInteger signature = rsa.signFile("src/main/resources/input2.txt");

            try (BufferedWriter writer = new BufferedWriter(new FileWriter("src/main/resources/signature.txt"))) {
                writer.write(signature.toString());
            }

            boolean isSignatureValid = rsa.verifySignatureOfFile("src/main/resources/input2.txt", signature);
            System.out.println("Is Signature Valid: " + isSignatureValid);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}