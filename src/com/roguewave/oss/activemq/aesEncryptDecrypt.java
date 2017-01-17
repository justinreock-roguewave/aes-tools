package com.roguewave.oss.activemq;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class aesEncryptDecrypt {

    private static Key aesKey = null;
    private static Cipher cipher = null;
	
    private static void init(String keyStr) throws Exception {
        if (keyStr == null || keyStr.length() != 16) {
            throw new Exception("Bad aes key entered");
        }
        if (aesKey == null) {
            aesKey = new SecretKeySpec(keyStr.getBytes(), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        }
    }
	
    public static String encrypt(String text, String key) throws Exception {
    	init(key);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
        return toHexString(cipher.doFinal(text.getBytes()));
    }
    
    public static String decrypt(String text, String key) throws Exception {
        init(key);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));
        return new String(cipher.doFinal(toByteArray(text)));
    }

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }    
	
	public static String encryptMessage(String mesgBody, String key) {
		

		try { 
		    mesgBody = encrypt(mesgBody, key);
		    mesgBody = Base64.getEncoder().encodeToString(mesgBody.getBytes());
		} 
		catch (Exception e) {
			System.out.println("Could not encrypt message\n" + e.getMessage());
			return "";
		}
		
		return mesgBody;
		
	}
	
	public static String decryptMessage(String mesgBody, String key) {
		
		
		try { 
			mesgBody = new String(Base64.getDecoder().decode(mesgBody),"utf-8");
			System.out.println("\nBase64 Decode Results:\n" + mesgBody);
		    mesgBody = decrypt(mesgBody, key);
		} 
		catch (Exception e) {
			System.out.println("Could not decrypt message\n" + e.getMessage());
			return "";
		}
		
		return mesgBody;
				
	}
	
	public static void main(String[] args) {

        BufferedReader br = null;
        String mode = "";
        String keyStr = "";
        String outputMesg = "";
        String payload = "";
        
        mode = args[0];
        if ("encrypt".equals(mode) || "decrypt".equals(mode)) {
        
        try {

            br = new BufferedReader(new InputStreamReader(System.in));
          
            System.out.println("Enter AES encryption key: ");
            keyStr = br.readLine();
                
            System.out.println("Enter payload text: ");
            payload = br.readLine();

            if ("encrypt".equals(mode)) {
            	
            	outputMesg = encryptMessage(payload,keyStr);
            	
            }
            
            if ("decrypt".equals(mode)) {
            	
            	outputMesg = decryptMessage(payload,keyStr);
            	
            }
                   

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        System.out.println("\nResults\n---------------------------------------------------------------------\nInput Text: \n" 
                            + payload + 
                            "\n\nMode: " 
                            + mode + 
                            "\nKey: " 
                            + keyStr +
                            "\n\nOutput Text\n---------------------------------------------------------------------\n" +
                            outputMesg + "\n\n");
              
        
        }
        
        else {
        	System.out.println("Invalid mode entered: " + mode);
        }

		
		
	}

}
