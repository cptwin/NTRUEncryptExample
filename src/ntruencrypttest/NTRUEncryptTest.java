/*
 * Copyright (C) 2015 Dajne Win
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package ntruencrypttest;

import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author d_win
 */
public class NTRUEncryptTest {
    
    private static byte ivBytes[];
    private static byte encryptedBuf[];
    private static byte wrappedAESKey[];

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            String pubkeyFile = "public_Key";
            String privkeyFile = "private_Key";
            Random prng = createSeededRandom();
            /*
            Valid values for OID are:
                ees401ep1
                ees449ep1
                ees677ep1
                ees1087ep2
                ees541ep1
                ees613ep1
                ees887ep1
                ees1171ep1
                ees659ep1
                ees761ep1
                ees1087ep1
                ees1499ep1
            */
            OID oid = parseOIDName("ees1499ep1");
            NtruEncryptKey ntruKeys = setupNtruEncryptKey(prng, oid, pubkeyFile, privkeyFile);
            encryptMessage(ntruKeys, prng, "Hello World!");
            System.out.println("Encrypted: " + new String(encryptedBuf));
            System.out.println("Decrypted: " + decryptMessage(ntruKeys, new String(encryptedBuf)));
            
        } catch (IOException | NtruException ex) {
            Logger.getLogger(NTRUEncryptTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    static Random createSeededRandom() {
        byte seed[] = new byte[32];
        java.util.Random sysRand = new java.util.Random();
        sysRand.nextBytes(seed);
        Random prng = new Random(seed);
        return prng;
    }

    static OID parseOIDName(
            String requestedOid) {
        try {
            return OID.valueOf(requestedOid);
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid OID! Valid values are:");
            for (OID oid : OID.values()) {
                System.out.println("  " + oid);
            }
            System.exit(1);
        }
        return null;
    }

    public static NtruEncryptKey setupNtruEncryptKey(Random prng, OID oid, String pubFileName, String privFileName) throws IOException, NtruException {
        NtruEncryptKey k = NtruEncryptKey.genKey(oid, prng);

        FileOutputStream pubFile = new FileOutputStream(pubFileName);
        pubFile.write(k.getPubKey());
        pubFile.close();

        FileOutputStream privFile = new FileOutputStream(privFileName);
        privFile.write(k.getPrivKey());
        privFile.close();
        
        return k;
    }

    public static String encryptMessage(NtruEncryptKey ntruKey, Random prng, String message) throws NtruException
    {
        String output = "";
        byte buf[] = message.getBytes();
        
        try
        {
            // Get an AES key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();
            
            // Get an IV
            ivBytes = new byte[16];
            prng.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the plaintext, then zero it out
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            encryptedBuf = cipher.doFinal(buf);
            java.util.Arrays.fill(buf, (byte)0);

            // Wrap the AES key with the NtruEncrypt key
            byte aesKeyBytes[] = aesKey.getEncoded();
            wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
            java.util.Arrays.fill(aesKeyBytes, (byte)0);

        } catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }
        output += ivBytes.length +"\n";
        output += ivBytes +"\n";
        output += wrappedAESKey.length +"\n";
        output += wrappedAESKey +"\n";
        output += encryptedBuf.length +"\n";
        output += encryptedBuf +"\n";
        return output;
    }
    
    public static String decryptMessage(NtruEncryptKey ntruKey, String cipherText) throws NtruException
    {
        byte wrappedKey[] = wrappedAESKey;
        byte encFileContents[] = encryptedBuf;
        byte fileContents[] = null;
        try
        {
            // Unwrap the AES key
            byte aesKeyBytes[] = ntruKey.decrypt(wrappedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);
            
            // Decrypt the file contents
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            fileContents = cipher.doFinal(encFileContents);
        } catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }
        return new String(fileContents);
    }

}
