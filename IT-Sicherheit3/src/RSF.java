import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class RSF {

	String rsaPrv, rsaPub, dokument, ssfFile;  //Eingabeparameter
	PublicKey pubKey = null;   // Öffentlicher RSA Schlüssel
	PrivateKey prvKey = null;  // Privater RSA Schlüssel
	byte[] aeskey = null;      // AES Schlüssel
	byte[] encryptedAesKey;    // AES Schlüssel, mit Oeffentlichen RSA Schlüssel verschlüsselt
	byte[] signature = null;   // AES Signatur
	byte[] encryptedDokument = null; // Das mit AES verschlüsselte Dokument

	public RSF(String rsaPrv, String rsaPub, String ssfFile , String dokument) {
		this.rsaPrv = rsaPrv;
		this.rsaPub = rsaPub;
		this.dokument = dokument;
		this.ssfFile = ssfFile;
	}

	public static void main(String[] args) {
		
		RSF rsf = new RSF(args[0], args[1], args[2], args[3]);
		
		//Public Key einlesen+
		rsf.readRSAPublic();
		
		//Private Key einlesen
		rsf.readRSAPrivate();
		
		//ssf Datei einlesen
		rsf.readSsfFile();
		
		
		
		
	}

	
	
	
	/**
	 * Diese Methode liest aus einer der Pub Datei, den Public RSA Schlüssel aus, Und
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
			Error("readRSAPublic(): Datei-Fehler beim Lesen der Nachricht!", e);
		}


		try {

			// nun wird aus der Kodierung wieder ein Öffentlicher Schlüssel erzeugt
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array können wir eine X.509-Schlüsselspezifikation erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);

			// und in einen abgeschlossene, providerabhängigen Schlüssel konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPublic(): Es existiert keine Implementierung für RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPublic() :Fehler beim Konvertieren des Öffentlichen Schlüssels.", e);
			e.printStackTrace();
		}

	}
	
	
	
	
	/**
	 * Diese Methode liest aus einer der prv Datei, den Private RSA Schlüssel aus, Und
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
			Error("readRSAPrivate(): Datei-Fehler beim Lesen der Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

			// nun wird aus der Kodierung wieder ein Privater Schlüssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array können wir eine PKCS8-Schlüsselspezifikationerzeugen
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(prvKeyEnc); // warum PKCS8???
			// und in einen abgeschlossene, providerabhängigen Schlüssel konvertieren
			prvKey = keyFac.generatePrivate(privateKeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPrivate(): Es existiert keine Implementierung für RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPrivate(): Fehler beim Konvertieren des Privaten Schlüssels.", e);
			e.printStackTrace();
		}

	}
	
	
	
	/**
	 * Dieses Methode liest eine ssf Datei aus mit vollgenden Werten:
	 * Länge des verschlüsselten geheimen Schlüssels (integer)
	 * Verschlüsselter geheimer Schlüssel (Bytefolge)
	 * Länge der Signatur des geheimen Schlüssels (integer)
	 * Signatur des geheimen Schlüssels (Bytefolge)
	 * Verschlüsselte Dateidaten (Bytefolge)
	 * 
	 * 
	 */
	
	
	public void readSsfFile(){
		
		
		try {
			// die Datei wird geöffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(new FileInputStream(ssfFile));
			
		
			// die Länge des verschlüsselten geheimen AES Schlüssels
			int laengeAES = is.readInt();
			encryptedAesKey = new byte[laengeAES];
			// verschlüsselten geheimen AES Schlüssels
			is.read(encryptedAesKey );

			// die Länge der Signatur des AES Schlüssels
			int laengeSignatur = is.readInt();
			signature = new byte[laengeSignatur];
			// die Signatur des AES Schlüssels
			is.read(signature);
		    
		
		    //Verschlüsselte Dokument Daten einlesen
			File file = new File(ssfFile); // geht das auch anders???
			int laenge = (int) file.length();
			encryptedDokument = new byte[laenge];
			is.read(encryptedDokument, laengeAES+laengeSignatur, laenge);
			is.close();
		
		
		
		} catch (FileNotFoundException e) {
			Error("readSsfFile(): Fehler beim einlesen der ssf Datei.", e);
		} catch (IOException e) {
			Error("readSsfFile(): Fehler beim einlesen der ssf Datei.", e);
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
