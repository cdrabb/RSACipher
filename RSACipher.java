
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.util.*;

public class RSACipher {

	public static void main(String [] args)
	{
		Scanner kb = new Scanner(System.in);
		int keyChoice = 0;
		int keySize = 0;
		String filePath;
		ObjectInputStream keyIn;
		ObjectOutputStream out;
		
		while(keyChoice > 3 || keyChoice < 1)
		{
			System.out.println("Choose key length: \n1. 512 bits\n"
						+ "2. 1024 bits\n3. 2048 bits");
			keyChoice = kb.nextInt();
		}
		if(keyChoice == 1)
			keySize = 512;
		else if(keyChoice == 2)
			keySize = 1024;
		else if(keyChoice == 3)
			keySize = 2048;
		
		try {
			
			//Generate Keys
			
			KeyPairGenerator pairgen;
			pairgen = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = new SecureRandom();
	        pairgen.initialize(keySize, random);
	        KeyPair keyPair = pairgen.generateKeyPair();
	        out = new ObjectOutputStream(new FileOutputStream("public.txt"));
            out.writeObject(keyPair.getPublic());
            out.close();
            out = new ObjectOutputStream(new FileOutputStream("private.txt"));
            out.writeObject(keyPair.getPrivate());
            out.close();
            
            System.out.println("Enter a file to encrypt: ");
            filePath = kb.next();
            File file = new File(filePath);
            
            
            //Encrypt
            
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(random);
            SecretKey key = keygen.generateKey();
            
            
            keyIn = new ObjectInputStream(new FileInputStream("public.txt"));
            
            
            Key publicKey = (Key) keyIn.readObject();
            keyIn.close();
            
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] wrappedKey = cipher.wrap(key);
            DataOutputStream dataOut = new DataOutputStream(new FileOutputStream("cipher.txt"));
            dataOut.writeInt(wrappedKey.length);
            dataOut.write(wrappedKey);

            InputStream in = new FileInputStream(file);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            crypt(in, dataOut, cipher);
            in.close();
            out.close();
            
            
            //Decrypt
            
            DataInputStream dataIn = new DataInputStream(new FileInputStream("cipher.txt"));
            int length = dataIn.readInt();
            wrappedKey = new byte[length];
            dataIn.read(wrappedKey, 0, length);
            
            keyIn = new ObjectInputStream(new FileInputStream("private.txt"));
            Key privateKey = (Key) keyIn.readObject();
            keyIn.close();
            
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            Key dKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            
            OutputStream os = new FileOutputStream("decipher.txt");
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, dKey);

            crypt(dataIn, os, cipher);
            dataIn.close();
            os.close();
            
            
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		
	}
	
	public static void crypt(InputStream in, OutputStream out, Cipher cipher) throws IOException, GeneralSecurityException
	{
		int blockSize = cipher.getBlockSize();
		int outputSize = cipher.getOutputSize(blockSize);
		byte[] inBytes = new byte[blockSize];
		byte[] outBytes = new byte[outputSize];

		int inLength = 0;
 
		boolean more = true;
		while (more)
		{
			inLength = in.read(inBytes);
			if (inLength == blockSize)
			{
				int outLength = cipher.update(inBytes, 0, blockSize, outBytes);
				out.write(outBytes, 0, outLength);
			}
			else more = false;
		}
		if (inLength > 0) outBytes = cipher.doFinal(inBytes, 0, inLength);
		else outBytes = cipher.doFinal();
		out.write(outBytes);
	}
}
