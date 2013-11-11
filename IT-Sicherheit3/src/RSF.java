import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class RSF {

	String rsaPrv, rsaPub, dokument, ssfFile; // Eingabeparameter
	PublicKey pubKey = null; // �ffentlicher RSA Schl�ssel
	PrivateKey prvKey = null; // Privater RSA Schl�ssel
	byte[] aeskey = null; // AES Schl�ssel
	byte[] encryptedAesKey; // AES Schl�ssel, mit Oeffentlichen RSA Schl�ssel
							// verschl�sselt
	byte[] signature = null; // AES Signatur
	byte[] encryptedDokument = null; // Das mit AES verschl�sselte Dokument
	byte[] decryptedDokument = null; // Das entschl�sselte Dokument

	public RSF(String rsaPrv, String rsaPub, String ssfFile, String dokument) {
		this.rsaPrv = rsaPrv;
		this.rsaPub = rsaPub;
		this.dokument = dokument;
		this.ssfFile = ssfFile;
	}

	public static void main(String[] args) {

		RSF rsf = new RSF(args[0], args[1], args[2], args[3]);

		// Public Key einlesen+
		rsf.readRSAPublic();

		// Private Key einlesen
		rsf.readRSAPrivate();

		// ssf Datei einlesen
		rsf.readSsfFile();

		// geheimen Schl�ssel entschl�sseln
		rsf.decryptAESKey();

		// Dokument enschluesseln und in die Augabe Datei schreiben
		rsf.decryptDokument();

		// signatur checken
		Boolean ok = rsf.verify();
		
		//wenn signatur Fehlerhaft, Fehler ausgabe
		if(ok == false){
			System.out.println("Die Signatur ist Fehlerhaft!!!");
		}
	}

	/**
	 * Diese Methode liest aus einer der Pub Datei, den Public RSA Schl�ssel
	 * aus, Und generiert daraus ein neues PublicKey Objekt
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

			// nun wird aus der Kodierung wieder ein �ffentlicher Schl�ssel
			// erzeugt
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array k�nnen wir eine X.509-Schl�sselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);

			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel
			// konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPublic(): Es existiert keine Implementierung f�r RSA.",
					e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPublic() :Fehler beim Konvertieren des �ffentlichen Schl�ssels.",
					e);
			e.printStackTrace();
		}

	}

	/**
	 * Diese Methode liest aus einer der prv Datei, den Private RSA Schl�ssel
	 * aus, Und generiert daraus ein neues PrivateKey Objekt
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
			// aus dem Byte-Array k�nnen wir eine
			// PKCS8-Schl�sselspezifikationerzeugen
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(prvKeyEnc); // warum
																				// PKCS8???
			// und in einen abgeschlossene, providerabh�ngigen Schl�ssel
			// konvertieren
			prvKey = keyFac.generatePrivate(privateKeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPrivate(): Es existiert keine Implementierung f�r RSA.",
					e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPrivate(): Fehler beim Konvertieren des Privaten Schl�ssels.",
					e);
			e.printStackTrace();
		}

	}

	/**
	 * Dieses Methode liest eine ssf Datei aus mit vollgenden Werten: L�nge des
	 * verschl�sselten geheimen Schl�ssels (integer) Verschl�sselter geheimer
	 * Schl�ssel (Bytefolge) L�nge der Signatur des geheimen Schl�ssels
	 * (integer) Signatur des geheimen Schl�ssels (Bytefolge) Verschl�sselte
	 * Dateidaten (Bytefolge)
	 * 
	 * 
	 */

	public void readSsfFile() {

		try {
			// die Datei wird ge�ffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(new FileInputStream(
					ssfFile));

			// die L�nge des verschl�sselten geheimen AES Schl�ssels
			int laengeAES = is.readInt();
			encryptedAesKey = new byte[laengeAES];
			// verschl�sselten geheimen AES Schl�ssels
			is.read(encryptedAesKey);

			// die L�nge der Signatur des AES Schl�ssels
			int laengeSignatur = is.readInt();
			signature = new byte[laengeSignatur];
			// die Signatur des AES Schl�ssels
			is.read(signature);

			// Verschl�sselte Dokument Daten einlesen
			File file = new File(ssfFile); // geht das auch anders???
			int laenge = (int) file.length();
			encryptedDokument = new byte[laenge];
			is.read(encryptedDokument, laengeAES + laengeSignatur, laenge);
			is.close();

		} catch (FileNotFoundException e) {
			Error("readSsfFile(): Fehler beim einlesen der ssf Datei.", e);
		} catch (IOException e) {
			Error("readSsfFile(): Fehler beim einlesen der ssf Datei.", e);
		}

	}

	/**
	 * Diese Methode entschl�sselt den AES Schl�ssel aus der ssf Datei
	 */

	private void decryptAESKey() {

		try {
			// Cipher Instance erzeugen
			Cipher cipher = Cipher.getInstance("RSA");

			// Cipher Objekt initialisieren
			cipher.init(Cipher.DECRYPT_MODE, prvKey);

			// AES Schl�ssel entschl�sseln
			aeskey = cipher.doFinal(encryptedAesKey);

		} catch (NoSuchAlgorithmException e) {
			Error("decryptAESKey(): Keine Implementierung f�r RSA", e);
		} catch (NoSuchPaddingException e) {
			Error("decryptAESKey(): Keine Implementierung f�r das Padding", e);
		} catch (InvalidKeyException e) {
			Error("decryptAESKey(): Ung�ltig formatierter Schl�ssel", e);
		} catch (IllegalBlockSizeException e) {
			Error("decryptAESKey(): Blockgroessen Fehler", e);
		} catch (BadPaddingException e) {
			Error("decryptAESKey(): Padding Fehler", e);
		}

	}

	/**
	 * 
	 * Entschl�sselt mit dem AES Schl�ssel das Dokument und schreibt den
	 * entschl�sselten Inhalt in die Ausgabe Datei
	 * 
	 */

	public void decryptDokument() {

		try {

			// Cipher Instance erzeugen
			Cipher cipher = Cipher.getInstance("AES");

			SecretKeySpec specKey2 = new SecretKeySpec(aeskey, "AES");

			// Cipher Objekt initialisieren
			cipher.init(Cipher.DECRYPT_MODE, specKey2);

			// Dokument entschl�sseln
			decryptedDokument = cipher.doFinal(encryptedDokument);

			// String s3 = new String(encryptedBytes2);
			// System.out.println(s3);

			// Erstellt einen neuen Output Stream
			DataOutputStream out = new DataOutputStream((new FileOutputStream(
					dokument)));

			// Schreibt Daten in die Ausgabedatei
			out.write(decryptedDokument);

			// Schlie�en der Datei
			out.close();

		} catch (NoSuchAlgorithmException e) {
			Error("decryptDokument(): Keine Implementierung f�r AES", e);
		} catch (NoSuchPaddingException e) {
			Error("decryptDokument(): Keine Implementierung f�r das Padding", e);
		} catch (InvalidKeyException e) {
			Error("decryptDokument(): Ung�ltig formatierter Schl�ssel", e);
		} catch (IllegalBlockSizeException e) {
			Error("decryptDokument():  Blockgroessen Fehler", e);
		} catch (BadPaddingException e) {
			Error("decryptDokument(): Padding Fehler", e);
		} catch (FileNotFoundException e) {
			Error("decryptDokument(): Datei Fehler", e);
		} catch (IOException e) {
			Error("decryptDokument(): Datei Fehler", e);
		}

	}

	/**
	 * 
	 * Diese Methode entschl�sselt die Signatur mit dem �ffentlichen
	 * RSA-Schl�ssel Und vergleicht in mit dem AES Schluessel
	 */

	private boolean verify() {

		try {

			// Nun wird die Signatur �berpr�ft
			// als Erstes erzeugen wir das Signatur-Objekt
			Signature rsaSig = Signature.getInstance("SHA1withRSA");

			// zum Verifizieren ben�tigen wir den �ffentlichen Schl�ssel
			rsaSig.initVerify(pubKey);

			// Daten zum Verifizieren liefern
			rsaSig.update(aeskey);  //oder encryptedAesKey???

			return rsaSig.verify(signature);

		} catch (InvalidKeyException e) {
			Error("verify()", e);
		} catch (SignatureException e) {
			Error("verify()", e);
		} catch (NoSuchAlgorithmException e) {
			Error("verify()", e);
		}

		return true;
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
