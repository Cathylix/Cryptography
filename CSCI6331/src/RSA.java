import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class RSA {
	static KeyPairGenerator keyPairGen;
	static KeyPair keyPair;
	static RSAPrivateKey privateKey;
	static RSAPublicKey publicKey;
	
	
	private static final int MAX_ENCRYPT_BLOCK = 117;

	private static final int MAX_DECRYPT_BLOCK = 128;
	
	static{

		try {
			privateKey = loadPrivateKeyByStr(readString("private.txt"));
			publicKey = loadPublicKeyByStr(readString("public.txt"));
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		File file = new File("c://test//ass2.zip");
		File newFile = new File("c://test//ass2e.zip");
		encryptFile(file, newFile);				
				
		File file1 = new File("c://test//ass2e.zip");
		File newFile1 = new File("c://test//ass2.zip");
		decryptFile(file1, newFile1);
		
	}
	
	public static void encryptFile(File file, File newFile) {
		try {
			InputStream is = new FileInputStream(file);
			OutputStream os = new FileOutputStream(newFile);
			byte[] bytes = new byte[MAX_ENCRYPT_BLOCK];
			while (is.read(bytes) > 0) {
				byte[] e=encryptByKey(bytes, publicKey);
				bytes = new byte[MAX_ENCRYPT_BLOCK];
				os.write(e, 0, e.length);
			}
			os.close();
			is.close();
			System.out.println("write success");
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		file.delete();
	}
	
	public static void decryptFile(File file, File newFile) {
		try {
			InputStream is = new FileInputStream(file);
			OutputStream os = new FileOutputStream(newFile);
			byte[] bytes1 = new byte[MAX_DECRYPT_BLOCK];
			while (is.read(bytes1) > 0) {
				byte[] de = decryptByKey(bytes1, privateKey);
				bytes1 = new byte[MAX_DECRYPT_BLOCK];
				os.write(de, 0, de.length);
			}
			os.close();
			is.close();
			System.out.println("write success");
		} catch (Exception e) {
			e.printStackTrace();
		}
		file.delete();
	}
	/** */
	/**
	 * * Encrypt String. *
	 * 
	 * @return byte[]
	 */
	protected byte[] encrypt(RSAPublicKey publicKey, byte[] obj) {
		if (publicKey != null) {
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
				return cipher.doFinal(obj);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	/** */
	/**
	 * * Basic decrypt method *
	 * 
	 * @return byte[]
	 */
	protected byte[] decrypt(RSAPrivateKey privateKey, byte[] obj) {
		if (privateKey != null) {
			try {
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				return cipher.doFinal(obj);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	public static byte[] encryptByKey(byte[] data, Key key) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		int length = data.length;
		int offset = 0;
		byte[] result = null;
		int i = 0;
		while (length - offset > 0) {
			byte[] cache = null;
			try {
			
				if (length - offset > MAX_ENCRYPT_BLOCK) {
					cache = cipher.doFinal(data, offset, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(data, offset, length - offset);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			result = concat(result, cache);
			i++;
			offset = i * MAX_ENCRYPT_BLOCK;
		}
		return result;
	}
	
	private static byte[] concat(byte[] buf1, byte[] buf2) {
		byte[] bufret = null;
		int len1 = 0;
		int len2 = 0;
		if (buf1 != null)
			len1 = buf1.length;
		if (buf2 != null)
			len2 = buf2.length;
		if (len1 + len2 > 0)
			bufret = new byte[len1 + len2];
		if (len1 > 0)
			System.arraycopy(buf1, 0, bufret, 0, len1);
		if (len2 > 0)
			System.arraycopy(buf2, 0, bufret, len1, len2);
		return bufret;
	}
	
	public static byte[] decryptByKey(byte data[], Key key) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		int length = data.length;
		int offset = 0;
		byte[] result = null;
		int i = 0;
		while (length - offset > 0) {
			byte[] cache = null;
			try {
			
				if (length - offset > MAX_DECRYPT_BLOCK) {
					cache = cipher.doFinal(data, offset, MAX_DECRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(data, offset, length - offset);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			result = concat(result, cache);
			i++;
			offset = i * MAX_DECRYPT_BLOCK;
		}

		return result;
	}
	
	public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)  
            throws Exception {  
        try {
        	sun.misc.BASE64Decoder base64DE = new sun.misc.BASE64Decoder();
            byte[] buffer = base64DE.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);  
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);  
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("not have this algorithm");  
        } catch (InvalidKeySpecException e) {  
            throw new Exception("key is illegality");  
        } catch (NullPointerException e) {  
            throw new Exception("key is empty");  
        }  
    }
	
	public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr)  
            throws Exception {
        try {
        	sun.misc.BASE64Decoder base64DE = new sun.misc.BASE64Decoder();
            byte[] buffer = base64DE.decodeBuffer(privateKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);  
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec); 
        } catch (NoSuchAlgorithmException e) {  
            throw new Exception("not have this algorithm");  
        } catch (InvalidKeySpecException e) {  
            throw new Exception("key is illegality");  
        } catch (NullPointerException e) {  
            throw new Exception("key is empty");  
        }  
    }
	
	public static String readString(String path) throws IOException

    {

        FileInputStream inStream= new FileInputStream(path);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer=new byte[1024];

        int length = -1;
        while( (length = inStream.read(buffer)) != -1)
        {
            bos.write(buffer,0,length);
        }

        bos.close();
        inStream.close();
        return bos.toString();   

    }
}