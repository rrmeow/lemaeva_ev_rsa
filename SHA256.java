import java.nio.ByteBuffer;
import java.nio.ByteOrder;

// хэширование через SHA-256
public class SHA256 {
    
    // начальные значения хэша (от корней первых 8 простых (32 бита дробных))
    private static final int[] INITIAL_HASH = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // константы (от куб корнейпервых 64 простых)
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    // само вычисление
    public static byte[] hash(byte[] data) {
        // дополнение
        byte[] padded = padMessage(data);
        
        // инициализация хэша
        int[] hash = INITIAL_HASH.clone();
        
        // обработка по блокам
        for (int i = 0; i < padded.length; i += 64) {
            processBlock(padded, i, hash);
        }
        
        // преобразуем из массива инт в массив байт
        return intArrayToByteArray(hash);
    }
    
    // описание метода дополнения
    private static byte[] padMessage(byte[] message) {
        // длина исходного текста в битах
        long originalBitLength = (long) message.length * 8;
        
        // вычисление дополненного текста (длина = 448 мод 512)
        int paddingLength = 64 - (message.length % 64);
        if (paddingLength <= 8) {
            paddingLength += 64;
        }
        
        // сам дополненный массив
        byte[] padded = new byte[message.length + paddingLength];
        
        // копируем в массив исходник
        System.arraycopy(message, 0, padded, 0, message.length);
        
        // добавление 1 бита
        padded[message.length] = (byte) 0x80;
        
        // попутно были добавлены нули
        
        // завершаем длиной исходного текста в битах
        int lengthPosition = padded.length - 8;
        for (int i = 0; i < 8; i++) {
            padded[lengthPosition + i] = (byte) (originalBitLength >>> (56 - i * 8));
        }
        
        return padded;
    }
    
    // обработка блока 512 бит
    private static void processBlock(byte[] block, int offset, int[] hash) {
        // W[0..63]
        int[] W = new int[64];
        
        // первые 16 слов - прямое разбиение блока
        for (int i = 0; i < 16; i++) {
            W[i] = ((block[offset + i * 4] & 0xFF) << 24) |
                   ((block[offset + i * 4 + 1] & 0xFF) << 16) |
                   ((block[offset + i * 4 + 2] & 0xFF) << 8) |
                   (block[offset + i * 4 + 3] & 0xFF);
        }
        
        // остальные 48 слов по формуле
        for (int i = 16; i < 64; i++) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }
        
        // рабочих переменные (текущие значения хэша)
        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];
        int e = hash[4];
        int f = hash[5];
        int g = hash[6];
        int h = hash[7];
        
        // 64 раунда сжатия
        for (int i = 0; i < 64; i++) {
            int T1 = h + bigSigma1(e) + ch(e, f, g) + K[i] + W[i];
            int T2 = bigSigma0(a) + maj(a, b, c);
            
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        // обновление хэш-значений
        hash[0] = a + hash[0];
        hash[1] = b + hash[1];
        hash[2] = c + hash[2];
        hash[3] = d + hash[3];
        hash[4] = e + hash[4];
        hash[5] = f + hash[5];
        hash[6] = g + hash[6];
        hash[7] = h + hash[7];
    }
    
    // вспомогательные математические методы
    // & - логическое и
    // xor - исключающее или
    // not - логическое отрицание
    // ROTR - циклический сдвиг вправо

    // функция выбора ch(x, y, z) = (x & y) xor (not(x) & z)
    private static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }
    
    // функция большинства maj(x, y, z) = (x & y) xor (x & z) xor (y & z)
    private static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    // циклические сдвиги
    // Σ_0(x) = ROTR(x, 2) xor ROTR(x, 13) xor ROTR(x, 22)
    private static int bigSigma0(int x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }
    
    // Σ_1(x) = ROTR(x, 6) xor ROTR(x, 11) xor ROTR(x, 25)
    private static int bigSigma1(int x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }
    
    // σ_0(x) = ROTR(x, 7) xor ROTR(x, 18) xor SHR(x, 3)
    private static int sigma0(int x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
    }
    
    // σ_1(x) = ROTR(x, 17) xor ROTR(x, 19) xor SHR(x, 10)
    private static int sigma1(int x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >>> 10);
    }
    
    // описание цикл сдвига вправо
    private static int rotateRight(int x, int n) {
        return (x >>> n) | (x << (32 - n));
    }
    
    // Преобразование массива int[8] в byte[32]
    private static byte[] intArrayToByteArray(int[] arr) {
        ByteBuffer buffer = ByteBuffer.allocate(arr.length * 4);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        for (int value : arr) {
            buffer.putInt(value);
        }
        
        return buffer.array();
    }
    
    // хэш в шестнадцатеричную строку
    public static String hashToHex(byte[] hash) {
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b & 0xFF));
        }
        return hex.toString();
    }
}