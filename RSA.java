import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

// основной код (генерация ключей, сам алгоритм и подпись)
public class RSA {
    
    private static final SecureRandom random = new SecureRandom();
    private static final int CERTAINTY = 100; // вер-ть простоты для теста Миллера-Рабина
    
    // хранение ключей
    public static class KeyPair {
        public BigInteger modulus;          // n
        public BigInteger publicExponent;   // e
        public BigInteger privateExponent;  // d
        
        public KeyPair(BigInteger n, BigInteger e, BigInteger d) {
            this.modulus = n;
            this.publicExponent = e;
            this.privateExponent = d;
        }
    }
    
    // сам алгоритм генерации по описанному в теории
    public static KeyPair generateKeyPair(int keySize) {
        System.out.println("Генерация ключей RSA " + keySize + " бит...");
        
        // рандомные большие простые числа
        int primeSize = keySize / 2;
        BigInteger p = generateLargePrime(primeSize);
        BigInteger q = generateLargePrime(primeSize);
        
        // это чтобы p и q были точно разные
        while (p.equals(q)) {
            q = generateLargePrime(primeSize);
        }
        
        // считаем n по которому будет модуль
        BigInteger n = p.multiply(q);
        
        // функция эйлера
        BigInteger phi = p.subtract(BigInteger.ONE)
                         .multiply(q.subtract(BigInteger.ONE));
        
        // открытая экспонента
        BigInteger e = new BigInteger("65537");
        
        // проверка на взаимную простоту
        while (!e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }
        
        // закрытая экспонента
        BigInteger d = e.modInverse(phi);
        
        System.out.println("Генерация завершена. Модуль n: " + n.toString(16).substring(0, 64) + "...");
        
        return new KeyPair(n, e, d);
    }
    
    // здесь генерируем простое число большой размерности
    private static BigInteger generateLargePrime(int bitLength) {
        BigInteger prime;
        do {
            // случайное нечетное число заданной длины
            prime = new BigInteger(bitLength, CERTAINTY, random);
        } while (!prime.isProbablePrime(CERTAINTY)); // проверяем тестом Миллера-Рабина на простоту
        
        return prime;
    }
    
    // тут считается хэш по SHA-256
    public static BigInteger computeFileHash(String filePath) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        
        // метод из другого класса
        byte[] hashBytes = SHA256.hash(fileBytes);
        
        // для красоты и отладки выводим
        System.out.println("Хэш SHA-256 вычислен, длина: " + hashBytes.length + " байт");
        
        // преобразование в бигинт (1 - положит знак)
        return new BigInteger(1, hashBytes);
    }
    
    // сама эцп
    public static String signFile(String inputFile, String privateKeyFile) throws Exception {
        System.out.println("Подписание файла: " + inputFile);
        
        // загрузка закрытого ключа
        KeyPair keys = loadKeyPair(privateKeyFile, true);
        
        // хэш
        BigInteger hash = computeFileHash(inputFile);
        System.out.println("Хэш файла (SHA-256): " + hash.toString(16));
        
        // хэш смотрим по модулю (берем по модулю если он превосходит его)
        if (hash.compareTo(keys.modulus) >= 0) {
            hash = hash.mod(keys.modulus);
        }
        
        // подпись по формуле из теор части
        BigInteger signature = hash.modPow(keys.privateExponent, keys.modulus);
        System.out.println("Подпись вычислена: " + signature.toString(16).substring(0, 64) + "...");
        
        // сохраняем
        String signatureFile = inputFile + ".sig";
        saveSignature(signature, signatureFile);
        
        return signatureFile;
    }
    
    // проверка подписи
    public static boolean verifySignature(String inputFile, String publicKeyFile) throws Exception {
        System.out.println("Проверка подписи для файла: " + inputFile);
        
        // загрузка открытого ключа
        KeyPair keys = loadKeyPair(publicKeyFile, false);
        
        // хэш
        BigInteger computedHash = computeFileHash(inputFile);
        System.out.println("Вычисленный хэш: " + computedHash.toString(16).substring(0, 64) + "...");
        
        // берем подпись из файла
        String signatureFile = inputFile + ".sig";
        BigInteger signature = loadSignature(signatureFile);
        
        // проверяем по формулам из теор части
        BigInteger recoveredHash = signature.modPow(keys.publicExponent, keys.modulus);
        System.out.println("Восстановленный хэш: " + recoveredHash.toString(16).substring(0, 64) + "...");
        
        // сравниваем хэши
        boolean isValid = computedHash.mod(keys.modulus).equals(recoveredHash);
        
        if (isValid) {
            System.out.println("Подписть верна");
        } else {
            System.out.println("Подпись неверна");
        }
        
        return isValid;
    }
    
    // тут сохраняем ключи
    public static void saveKeyPair(KeyPair keys, String privateKeyFile, String publicKeyFile) 
            throws IOException {
        
        // закрытый
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(privateKeyFile))) {
            oos.writeObject(keys.modulus);
            oos.writeObject(keys.privateExponent);
            System.out.println("Закрытый ключ сохранен в: " + privateKeyFile);
        }
        
        // открытый
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(publicKeyFile))) {
            oos.writeObject(keys.modulus);
            oos.writeObject(keys.publicExponent);
            System.out.println("Открытый ключ сохранен в: " + publicKeyFile);
        }
    }
    
    // тут загружаем ключи
    public static KeyPair loadKeyPair(String keyFile, boolean isPrivate) 
            throws IOException, ClassNotFoundException {
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(keyFile))) {
            BigInteger modulus = (BigInteger) ois.readObject();
            BigInteger exponent = (BigInteger) ois.readObject();
            
            if (isPrivate) {
                return new KeyPair(modulus, null, exponent);
            } else {
                return new KeyPair(modulus, exponent, null);
            }
        }
    }
    
    // сохранение подписи
    private static void saveSignature(BigInteger signature, String filename) 
        throws IOException {
    
    try (DataOutputStream dos = new DataOutputStream(
            new FileOutputStream(filename))) {
        // получение байтов
        byte[] sigBytes = signature.toByteArray();
        
        // запись длины
        dos.writeInt(sigBytes.length);
        
        // запись байтов
        dos.write(sigBytes);
        
        System.out.println("Подпись сохранена: " + filename + 
                         " (размер: " + sigBytes.length + " байт)");
    }
}
    
    // загрузка подписи
    private static BigInteger loadSignature(String filename) 
        throws IOException {
    
    try (DataInputStream dis = new DataInputStream(
            new FileInputStream(filename))) {
        // начинаем с длины массива
        int length = dis.readInt();
        
        // новый массив нужного размера
        byte[] sigBytes = new byte[length];
        
        // читаем байты
        dis.readFully(sigBytes);
        
        System.out.println("Подпись загружена: " + filename + 
                         " (размер: " + length + " байт)");
        
        return new BigInteger(sigBytes);
    }
}
    
    // генерация и сохранение ключей для графы
    public static void generateKeys(int keySize, String privateKeyFile, String publicKeyFile) 
            throws Exception {
        
        KeyPair keys = generateKeyPair(keySize);
        saveKeyPair(keys, privateKeyFile, publicKeyFile);
    }
}