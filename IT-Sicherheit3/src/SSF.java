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
 * SSF, verschl�sselt und signiert mit Hilfe von RSA und AES eine Datei
 * 
 * 
 * @author Timo Feddersen und Sergej Kimel
 * @version 1.0
 */

public class SSF {

	String rsaPrv, rsaPub, dataOut, dataVerify;
	PublicKey pubKey = null;     //�ffentlicher RSA Schl�ssel
	PrivateKey prvKey = null;    //Privater RSA Schl�ssel
	SecretKey aeskey = null;     //AES Schl�ssel
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
		
		//AES Schl�ssel erzeugen
		ssf.generateAESKey();
		
		//Signatur f�r den AES Schl�ssel erstellen (mit dem �ffentlichen RSA Schl�ssel)
//		ssf.signAESKey();
		
		//AES Schl�ssel mit dem Privaten RSA Schl�ssel verschl�sseln
	//	ssf.encryptAESKey();
	}

	/**
	 * Liest aus einer der Pub Datei, den Public RSA Schl�ssel aus, Und
	 * generiert daraus ein neues PublicKey Objekt
	 * 
	 */

	public void readRSAPublic() {

		byte[] inhaber = null;
		byte[] pubKeyEnc = null;

		try {
			// die Datei wird ge�ffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(
					new FileInputStream(rsaPub));

			// die L�nge des Inhabers
			int len = is.readInt();
			inhaber = new byte[len];
			// der Inhaber
        	is.read(inhaber);

			// die L�nge des schl�ssels
			len = is.readInt();
			pubKeyEnc = new byte[len];
			// der schl�ssel
			is.read(pubKeyEnc);
	
			is.close();

		} catch (IOException e) {
			Error("Datei-Fehler beim Lesen der signierten Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

		// nun wird aus der Kodierung wieder ein �ffentlidcher Schl�ssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array k�nnen wir eine X.509-Schl�sselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);
			
		
			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung f�r RSA.", e);
    	} catch (InvalidKeySpecException e) {
  			Error("Fehler beim Konvertieren des �ffentlichen Schl�ssels.", e);
			e.printStackTrace();
		}

	}

	/**
	 * Liest aus einer der prv Datei, den Private RSA Schl�ssel aus, Und
	 * generiert daraus ein neues PrivateKey Objekt
	 * 
	 */

	public void readRSAPrivate() {

		
		byte[] inhaber = null;
		byte[] prvKeyEnc = null;

		try {
			// die Datei wird ge�ffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(
					new FileInputStream(rsaPrv));

			// die L�nge des Inhabers
			int len = is.readInt();
			inhaber = new byte[len];
			// der Inhaber
			is.read(inhaber);

			// die L�nge des schl�ssels
			len = is.readInt();
			prvKeyEnc = new byte[len];
			// der schl�ssel
			is.read(prvKeyEnc);
			
			is.close();

		} catch (IOException e) {
			Error("Datei-Fehler beim Lesen der signierten Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

			// nun wird aus der Kodierung wieder ein Privater Schl�ssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array k�nnen wir eine X.509-Schl�sselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(prvKeyEnc);
			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel konvertieren
			prvKey = keyFac.generatePrivate(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung f�r RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("Fehler beim Konvertieren des Privaten Schl�ssels.", e);
			e.printStackTrace();
		}	
		

		
	}
	
	/**
	 * Erzeugt einen 128bit AES Schl�ssel
	 */
	
	public void generateAESKey(){
		
		try {
			
			
			KeyGenerator kg;
			// AES-Schl�ssel generieren
			kg = KeyGenerator.getInstance("AES");
			kg.init(128); // Schl�ssell�nge 128 Bit
			aeskey = kg.generateKey();

		} catch (NoSuchAlgorithmException e) {
			Error("Es existiert keine Implementierung f�r AES.", e);
		}
	
		
	}
	
	/**
	 * Erstellt eine Signatur des AES Schl�ssels mit dem privaten RSA Schl�ssel
	 */
	
	public void signAESKey(){
	
		
				Signature rsaSig = null;
			
				try {
					// als Erstes erzeugen wir das Signatur-Objekt
					rsaSig = Signature.getInstance("SHA1withRSA");
					// zum Signieren ben�tigen wir den geheimen Schl�ssel
					rsaSig.initSign(prvKey);
					// Daten zum Signieren liefern
					rsaSig.update(aeskey.getEncoded());
					// Signatur f�r die Daten erzeugen
					signature = rsaSig.sign();
				} catch (NoSuchAlgorithmException ex) {
					Error("Keine Implementierung f�r SHA1withRSA!", ex);
	
				} catch (InvalidKeyException e) {
					Error("Falscher Schl�ssel!", e);
				} catch (SignatureException e) {
					Error("Fehler beim Signieren der Nachricht!", e);
				}
	}
	
	
	
	/**
	 * Verschl�sselt den AES Schl�ssel mit dem Privaten RSA Schl�ssel
	 */
	
	
	public void encryptAESKey(){
		
		try {
			
			Cipher cipher = Cipher.getInstance("RSA");
			
			
		} catch (NoSuchAlgorithmException e) {
			Error("Keine Implementierung f�r RSA", e);
		} catch (NoSuchPaddingException e) {
			Error("", e);
		}
		
		
	}
	
	
	
	/**
	 * Verschl�sselt mit dem AES Key, das Dokument
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
			Error("Keine Implementierung f�r RSA", e);
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
	 *            eine Beschreibung f�r den Fehler
	 * @param ex
	 *            die Ausnahme, die den Fehler ausgel�st hat
	 */
	private final static void Error(String msg, Exception ex) {
		System.out.println(msg);
		System.out.println(ex.getMessage());
		System.exit(0);
	}

}
