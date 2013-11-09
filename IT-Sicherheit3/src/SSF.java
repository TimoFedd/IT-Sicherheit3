import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * 
 * SSF, verschlüsselt und signiert mit Hilfe von RSA und AES eine Datei
 * 
 * 
 * @author Timo Feddersen und Sergej Kimel
 * @version 1.0
 */

public class SSF {

	String rsaPrv, rsaPub, dataOut, dataVerify;
	PublicKey pubKey = null;     //Öffentlicher RSA Schlüssel
	PrivateKey prvKey = null;    //Privater RSA Schlüssel
	SecretKey aeskey = null;     //AES Schlüssel
	byte[] signature = null;     //AES Signatur

	public SSF(String rsaPrv, String rsaPub, String dataOut, String dataVerify) {
		this.rsaPrv = rsaPrv;
		this.rsaPub = rsaPub;
		this.dataOut = dataOut;
		this.dataVerify = dataVerify;
	}

	public static void main(String[] args) {

		SSF ssf = new SSF(args[0], args[1], args[2], args[3]);
		
		// Public key einlesen
		ssf.readRSAPublic();
		
		// Private Key einlesen
		ssf.readRSAPrivate();
		
		//AES Schlüssel erzeugen
		ssf.generateAESKey();
		
		//Signatur für den AES Schlüssel erstellen (mit dem Öffentlichen RSA Schlüssel)
//		ssf.signAESKey();
		
		//AES Schlüssel mit dem Privaten RSA Schlüssel verschlüsseln
	//	ssf.encryptAESKey();
	}

	/**
	 * Liest aus einer der Pub Datei, den Public RSA Schlüssel aus, Und
	 * generiert daraus ein neues PublicKey Objekt
	 * 
	 */

	public void readRSAPublic() {

		byte[] inhaber = null;
		byte[] pubKeyEnc = null;

		try {
			// die Datei wird geöffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(
					new FileInputStream(rsaPub));

			// die Länge des Inhabers
			int len = is.readInt();
			inhaber = new byte[len];
			// der Inhaber
        	is.read(inhaber);

			// die Länge des schlüssels
			len = is.readInt();
			pubKeyEnc = new byte[len];
			// der schlüssel
			is.read(pubKeyEnc);
	
			is.close();

		} catch (IOException e) {
			Error("Datei-Fehler beim Lesen der signierten Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

		// nun wird aus der Kodierung wieder ein Öffentlidcher Schlüssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array können wir eine X.509-Schlüsselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);
			
		
			// und in einen abgeschlossene, providerabhängigen Schlüssel konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung für RSA.", e);
    	} catch (InvalidKeySpecException e) {
  			Error("Fehler beim Konvertieren des Öffentlichen Schlüssels.", e);
			e.printStackTrace();
		}

	}

	/**
	 * Liest aus einer der prv Datei, den Private RSA Schlüssel aus, Und
	 * generiert daraus ein neues PrivateKey Objekt
	 * 
	 */

	public void readRSAPrivate() {

		
		byte[] inhaber = null;
		byte[] prvKeyEnc = null;

		try {
			// die Datei wird geöffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(
					new FileInputStream(rsaPrv));

			// die Länge des Inhabers
			int len = is.readInt();
			inhaber = new byte[len];
			// der Inhaber
			is.read(inhaber);

			// die Länge des schlüssels
			len = is.readInt();
			prvKeyEnc = new byte[len];
			// der schlüssel
			is.read(prvKeyEnc);
			
			is.close();

		} catch (IOException e) {
			Error("Datei-Fehler beim Lesen der signierten Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

			// nun wird aus der Kodierung wieder ein Privater Schlüssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array können wir eine X.509-Schlüsselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(prvKeyEnc);
			// und in einen abgeschlossene, providerabhängigen Schlüssel konvertieren
			prvKey = keyFac.generatePrivate(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung für RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("Fehler beim Konvertieren des Privaten Schlüssels.", e);
			e.printStackTrace();
		}	
		

		
	}
	
	/**
	 * Erzeugt einen 128bit AES Schlüssel
	 */
	
	public void generateAESKey(){
		
		try {
			
			
			KeyGenerator kg;
			// AES-Schlüssel generieren
			kg = KeyGenerator.getInstance("AES");
			kg.init(128); // Schlüssellänge 128 Bit
			aeskey = kg.generateKey();

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung für AES.", e);
		}
	
		
	}
	
	/**
	 * Erstellt eine Signatur des AES Schlüssels mit dem privaten RSA Schlüssel
	 */
	
	public void signAESKey(){
	
		
				Signature rsaSig = null;
			
				try {
					// als Erstes erzeugen wir das Signatur-Objekt
					rsaSig = Signature.getInstance("SHA1withRSA");
					// zum Signieren benötigen wir den geheimen Schlüssel
					rsaSig.initSign(prvKey);
					// Daten zum Signieren liefern
					rsaSig.update(aeskey.getEncoded());
					// Signatur für die Daten erzeugen
					signature = rsaSig.sign();
				} catch (NoSuchAlgorithmException ex) {
					Error("Keine Implementierung für SHA1withRSA!", ex);
	
				} catch (InvalidKeyException e) {
					Error("Falscher Schlüssel!", e);
				} catch (SignatureException e) {
					Error("Fehler beim Signieren der Nachricht!", e);
				}
	}
	
	
	
	/**
	 * Verschlüsselt den AES Schlüssel mit dem Privaten RSA Schlüssel
	 */
	
	
	public void encryptAESKey(){
		
		try {
			
			Cipher cipher = Cipher.getInstance("RSA");
			
			
		} catch (NoSuchAlgorithmException e) {
			Error("Keine Implementierung für RSA", e);
		} catch (NoSuchPaddingException e) {
			Error("", e);
		}
		
		
	}
	
	
	
	/**
	 * Verschlüsselt mit dem AES Key, das Dokument
	 */
	
	public void encryptDataout(){
	try {
			//AES Cipher objekt erzeugen
			Cipher cipher = Cipher.getInstance("AES");
			
			//Cipher Objekt mit dem aeskey initialisieren
			cipher.init(Cipher.ENCRYPT_MODE, aeskey);
			
			System.out.println("Cipher Parameter: "
					+ cipher.getParameters().toString());
			AlgorithmParameters ap = cipher.getParameters();
			
			
			
			
			
			
		} catch (NoSuchAlgorithmException e) {
			Error("Keine Implementierung für RSA", e);
		} catch (NoSuchPaddingException e) {
			Error("", e);
		} catch (InvalidKeyException e) {
			Error("", e);
		}
		
	}

	
	
	/**
	 * Diese Methode gibt eine Fehlermeldung sowie eine Beschreibung der
	 * Ausnahme aus. Danach wird das Programm beendet.
	 * 
	 * @param msg
	 *            eine Beschreibung für den Fehler
	 * @param ex
	 *            die Ausnahme, die den Fehler ausgelöst hat
	 */
	private final static void Error(String msg, Exception ex) {
		System.out.println(msg);
		System.out.println(ex.getMessage());
		System.exit(0);
	}

}
