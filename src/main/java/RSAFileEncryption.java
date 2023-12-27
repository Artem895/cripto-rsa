import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAFileEncryption {

    private static final int KEY_SIZE = 1024; // Размер ключа в битах
    private static final int BUFFER_SIZE = (KEY_SIZE / 8) - 11; // Размер буфера для шифрования/дешифрования RSA

    private BigInteger n, d, e;

    public void generateKeys() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(KEY_SIZE / 2, random);
        BigInteger q = BigInteger.probablePrime(KEY_SIZE / 2, random);

        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(65537);
        d = e.modInverse(phi);
    }

    public byte[] encrypt(byte[] data) {
        // Шифрование данных
        int dataLength = data.length;
        int blockSize = BUFFER_SIZE;
        int blocksCount = (int) Math.ceil((double) dataLength / blockSize);
        byte[] encryptedData = new byte[blocksCount * (KEY_SIZE / 8)];

        for (int i = 0; i < blocksCount; i++) {
            int blockLength = Math.min(blockSize, dataLength - i * blockSize);
            byte[] block = new byte[blockLength];
            System.arraycopy(data, i * blockSize, block, 0, blockLength);

            BigInteger message = new BigInteger(block);
            BigInteger encryptedMessage = message.modPow(d, n);
            byte[] encryptedBytes = encryptedMessage.toByteArray();

            // Копируем результат в выходной массив
            System.arraycopy(encryptedBytes, 0, encryptedData, i * (KEY_SIZE / 8) + (KEY_SIZE / 8 - encryptedBytes.length), encryptedBytes.length);
        }

        return encryptedData;
    }

    public byte[] decrypt(byte[] encryptedData) {
        // Дешифрование данных
        int encryptedDataLength = encryptedData.length;
        int blockSize = KEY_SIZE / 8;
        int blocksCount = encryptedDataLength / blockSize;
        byte[] decryptedData = new byte[blocksCount * BUFFER_SIZE];

        for (int i = 0; i < blocksCount; i++) {
            byte[] block = new byte[blockSize];
            System.arraycopy(encryptedData, i * blockSize, block, 0, blockSize);

            BigInteger encryptedMessage = new BigInteger(block);
            BigInteger decryptedMessage = encryptedMessage.modPow(e, n);
            byte[] decryptedBytes = decryptedMessage.toByteArray();

            // Копируем результат в выходной массив
            System.arraycopy(decryptedBytes, 0, decryptedData, i * BUFFER_SIZE, Math.min(BUFFER_SIZE, decryptedBytes.length));
        }

        return decryptedData;
    }

    public void encryptFile(String inputFile, String outputFile) throws IOException {
        try (InputStream inputStream = new FileInputStream(inputFile);
             OutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] encryptedBytes = encrypt(buffer);
                outputStream.write(encryptedBytes, 0, encryptedBytes.length);
            }
        }
    }

    public void decryptFile(String inputFile, String outputFile) throws IOException {
        try (InputStream inputStream = new FileInputStream(inputFile);
             OutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[KEY_SIZE / 8];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] decryptedBytes = decrypt(buffer);
                outputStream.write(decryptedBytes, 0, decryptedBytes.length);
            }
        }
    }

    public static void main(String[] args) {
        try {
            RSAFileEncryption rsa = new RSAFileEncryption();
            rsa.generateKeys();
            // Шифрование файла
            rsa.encryptFile("src/main/resources/input.txt", "src/main/resources/encrypted_text.txt");

            // Дешифрование файла
            rsa.decryptFile("src/main/resources/encrypted_text.txt", "src/main/resources/decryptedFile.txt");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}