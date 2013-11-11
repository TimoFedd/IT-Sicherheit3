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
	PublicKey pubKey = null;   // �ffentlicher RSA Schl�ssel
	PrivateKey prvKey = null;  // Privater RSA Schl�ssel
	byte[] aeskey = null;      // AES Schl�ssel
	byte[] encryptedAesKey;    // AES Schl�ssel, mit Oeffentlichen RSA Schl�ssel verschl�sselt
	byte[] signature = null;   // AES Signatur
	byte[] encryptedDokument = null; // Das mit AES verschl�sselte Dokument

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
	 * Diese Methode liest aus einer der Pub Datei, den Public RSA Schl�ssel aus, Und
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
			Error("readRSAPublic(): Datei-Fehler beim Lesen der Nachricht!", e);
		}


		try {

			// nun wird aus der Kodierung wieder ein �ffentlicher Schl�ssel erzeugt
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array k�nnen wir eine X.509-Schl�sselspezifikation erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);

			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPublic(): Es existiert keine Implementierung f�r RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPublic() :Fehler beim Konvertieren des �ffentlichen Schl�ssels.", e);
			e.printStackTrace();
		}

	}
	
	
	
	
	/**
	 * Diese Methode liest aus einer der prv Datei, den Private RSA Schl�ssel aus, Und
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
			Error("readRSAPrivate(): Datei-Fehler beim Lesen der Nachricht!", e);
		}

		KeyFactory keyFac;

		try {

			// nun wird aus der Kodierung wieder ein Privater Schl�ssel erzeugt
			keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array k�nnen wir eine PKCS8-Schl�sselspezifikationerzeugen
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(prvKeyEnc); // warum PKCS8???
			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel konvertieren
			prvKey = keyFac.generatePrivate(privateKeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPrivate(): Es existiert keine Implementierung f�r RSA.", e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPrivate(): Fehler beim Konvertieren des Privaten Schl�ssels.", e);
			e.printStackTrace();
		}

	}
	
	
	
	/**
	 * Dieses Methode liest eine ssf Datei aus mit vollgenden Werten:
	 * L�nge des verschl�sselten geheimen Schl�ssels (integer)
	 * Verschl�sselter geheimer Schl�ssel (Bytefolge)
	 * L�nge der Signatur des geheimen Schl�ssels (integer)
	 * Signatur des geheimen Schl�ssels (Bytefolge)
	 * Verschl�sselte Dateidaten (Bytefolge)
	 * 
	 * 
	 */
	
	
	public void readSsfFile(){
		
		
		try {
			// die Datei wird ge�ffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(new FileInputStream(ssfFile));
			
		
			// die L�nge des verschl�sselten geheimen AES Schl�ssels
			int laengeAES = is.readInt();
			encryptedAesKey = new byte[laengeAES];
			// verschl�sselten geheimen AES Schl�ssels
			is.read(encryptedAesKey );

			// die L�nge der Signatur des AES Schl�ssels
			int laengeSignatur = is.readInt();
			signature = new byte[laengeSignatur];
			// die Signatur des AES Schl�ssels
			is.read(signature);
		    
		
		    //Verschl�sselte Dokument Daten einlesen
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
