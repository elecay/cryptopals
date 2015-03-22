package set1;

import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.DatatypeConverter;

/**
 * 
 * @author Sebastian Rajo <elecay@gmail.com>
 */
public class Cryptopals {

    public static String hexToBase64(String hexString) {
        byte[] bytes = DatatypeConverter.parseHexBinary(hexString);
        Encoder encoder = Base64.getEncoder();
        return new String(encoder.encode(bytes));
    }

    public static String base64ToHex(String base64String) {
        Decoder decoder = Base64.getDecoder();
        byte[] decoded = decoder.decode(base64String);
        return new String(decoded);
    }

    public static String xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return null;
        }
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return DatatypeConverter.printHexBinary(result);
    }

    public static int[] xorCipher(byte[] cipherText) {
        int key = 0;
        int score = 0;

        // Points according their frequency
        // http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
        Map<Character, Integer> commons = new HashMap<>();
        commons.put('E', 120);
        commons.put('e', 120);
        commons.put('T', 91);
        commons.put('t', 91);
        commons.put('A', 81);
        commons.put('a', 81);
        commons.put('O', 77);
        commons.put('o', 77);
        commons.put('I', 73);
        commons.put('i', 73);
        commons.put('N', 69);
        commons.put('n', 69);
        
        // Non-alpha character position
        commons.put('?', 80);

        commons.put('S', 62);
        commons.put('s', 62);
        commons.put('H', 60);
        commons.put('h', 60);
        commons.put('R', 59);
        commons.put('r', 59);
        commons.put('D', 43);
        commons.put('d', 43);
        commons.put('L', 39);
        commons.put('l', 39);
        commons.put('U', 28);
        commons.put('u', 28);

        for (int z = Character.MIN_VALUE; z <= Character.MAX_VALUE; z++) {
            int points = 0;
            char[] result = new char[cipherText.length];
            for (int i = 0; i < cipherText.length; i++) {
                result[i] = (char) (cipherText[i] ^ z);
                if (!Character.isAlphabetic(result[i]) && !Character.isSpaceChar(result[i])) {
                    points -= commons.get('?');
                } else if (commons.containsKey(result[i])) {
                    points += commons.get(result[i]);
                }
            }
            if (points > score) {
                key = z;
                score = points;
            }
        }
        return new int[]{ key, score };
    }

    public static byte[] repeatingKeyXor(byte[] textInBytes, byte[] keyInBytes) {
        byte[] result = new byte[textInBytes.length + 1];
        for (int i = 0; i < textInBytes.length;) {
            for (int j = 0; j < keyInBytes.length; j++) {
                if (i == textInBytes.length) {
                    break;
                }
                result[i] = (byte) ((byte) keyInBytes[j] ^ textInBytes[i]);
                i++;
            }
        }
        return result;
    }

    public static int hammingDistance(byte[] from, byte[] to) {
        int distance = 0;
        for (int i = 0; i < from.length; i++) {
            distance += Integer.bitCount(from[i] ^ to[i]);
        }
        return distance;
    }
    
    public static byte[] breakingRepeatingKeyXor(byte[] textInBytes) {
        // Smallest distance. We can add distance of 3 or 4, etc., if we want to.
        Map <Integer, Boolean> validDistances = new HashMap<>();
        validDistances.put(1, true);
        validDistances.put(2, true);
        
        int[] keySizes = new int[40];
        // find the distances between substrings from 2 to 40 chars
        for (int i = 2; i < 40; i++) {
            keySizes[i] = ((hammingDistance(Arrays.copyOfRange(textInBytes, 0, i), Arrays.copyOfRange(textInBytes, i, i * 2))
                    + hammingDistance(Arrays.copyOfRange(textInBytes, i * 2, i * 3), Arrays.copyOfRange(textInBytes, i * 3, i * 4))) / 2) / i;
        }
        byte[] response = null;
        byte[] candidate = null;
        int totalScore = 0;
        int KEYSIZE = 0;
        // Find de best score for the smallest distances
        for (int z = 0; z < keySizes.length; z++) {
            if (!validDistances.containsKey(keySizes[z])) continue;
            
            if (response == null) response = new byte[KEYSIZE];
            int score = 0;
            KEYSIZE = z;
            candidate = new byte[KEYSIZE];
            
            byte[][] transposeBlocks = new byte[KEYSIZE][1];
            // filling the transpose with KEYSIZE blocks
            for (int i = 0; i < KEYSIZE; i++) {
                byte[] block = new byte[textInBytes.length / KEYSIZE + 1];
                transposeBlocks[i] = block;
            }
            // load each KEYSIZE block with values according their position on the main block
            for (int i = 0; i < textInBytes.length - KEYSIZE; i += KEYSIZE) {
                for (int j = 0; j < KEYSIZE; j++) {
                    transposeBlocks[j][i / KEYSIZE] = textInBytes[i + j];
                }
            }
            // find the key for each block
            for (int i = 0; i < KEYSIZE; i++) {
                int[] result = xorCipher(transposeBlocks[i]);
                int a = result[0];
                score += result[1];
                candidate[i] = (byte) a;
            }
            // tracks if this KEYSIZE has best score
            if (score > totalScore) {
                response = candidate;
                totalScore = score;
            }
        }
        return response;
    }
}
