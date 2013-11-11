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
	PublicKey pubKey = null; // Öffentlicher RSA Schlüssel
	PrivateKey prvKey = null; // Privater RSA Schlüssel
	byte[] aeskey = null; // AES Schlüssel
	byte[] encryptedAesKey; // AES Schlüssel, mit Oeffentlichen RSA Schlüssel
							// verschlüsselt
	byte[] signature = null; // AES Signatur
	byte[] encryptedDokument = null; // Das mit AES verschlüsselte Dokument
	byte[] decryptedDokument = null; // Das entschlüsselte Dokument

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

		// geheimen Schlüssel entschlüsseln
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
	 * Diese Methode liest aus einer der Pub Datei, den Public RSA Schlüssel
	 * aus, Und generiert daraus ein neues PublicKey Objekt
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

			// nun wird aus der Kodierung wieder ein Öffentlicher Schlüssel
			// erzeugt
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			// aus dem Byte-Array können wir eine X.509-Schlüsselspezifikation
			// erzeugen
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEnc);

			// und in einen abgeschlossene, providerabhängigen Schlüssel
			// konvertieren
			pubKey = keyFac.generatePublic(x509KeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPublic(): Es existiert keine Implementierung für RSA.",
					e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPublic() :Fehler beim Konvertieren des Öffentlichen Schlüssels.",
					e);
			e.printStackTrace();
		}

	}

	/**
	 * Diese Methode liest aus einer der prv Datei, den Private RSA Schlüssel
	 * aus, Und generiert daraus ein neues PrivateKey Objekt
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
			// aus dem Byte-Array können wir eine
			// PKCS8-Schlüsselspezifikationerzeugen
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(prvKeyEnc); // warum
																				// PKCS8???
			// und in einen abgeschlossene, providerabhängigen Schlüssel
			// konvertieren
			prvKey = keyFac.generatePrivate(privateKeySpec);

		} catch (NoSuchAlgorithmException e) {
			Error("readRSAPrivate(): Es existiert keine Implementierung für RSA.",
					e);
		} catch (InvalidKeySpecException e) {
			Error("readRSAPrivate(): Fehler beim Konvertieren des Privaten Schlüssels.",
					e);
			e.printStackTrace();
		}

	}

	/**
	 * Dieses Methode liest eine ssf Datei aus mit vollgenden Werten: Länge des
	 * verschlüsselten geheimen Schlüssels (integer) Verschlüsselter geheimer
	 * Schlüssel (Bytefolge) Länge der Signatur des geheimen Schlüssels
	 * (integer) Signatur des geheimen Schlüssels (Bytefolge) Verschlüsselte
	 * Dateidaten (Bytefolge)
	 * 
	 * 
	 */

	public void readSsfFile() {

		try {
			// die Datei wird geöffnet und die Daten gelesen
			DataInputStream is = new DataInputStream(new FileInputStream(
					ssfFile));

			// die Länge des verschlüsselten geheimen AES Schlüssels
			int laengeAES = is.readInt();
			encryptedAesKey = new byte[laengeAES];
			// verschlüsselten geheimen AES Schlüssels
			is.read(encryptedAesKey);

			// die Länge der Signatur des AES Schlüssels
			int laengeSignatur = is.readInt();
			signature = new byte[laengeSignatur];
			// die Signatur des AES Schlüssels
			is.read(signature);

			// Verschlüsselte Dokument Daten einlesen
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
	 * Diese Methode entschlüsselt den AES Schlüssel aus der ssf Datei
	 */

	private void decryptAESKey() {

		try {
			// Cipher Instance erzeugen
			Cipher cipher = Cipher.getInstance("RSA");

			// Cipher Objekt initialisieren
			cipher.init(Cipher.DECRYPT_MODE, prvKey);

			// AES Schlüssel entschlüsseln
			aeskey = cipher.doFinal(encryptedAesKey);

		} catch (NoSuchAlgorithmException e) {
			Error("decryptAESKey(): Keine Implementierung für RSA", e);
		} catch (NoSuchPaddingException e) {
			Error("decryptAESKey(): Keine Implementierung für das Padding", e);
		} catch (InvalidKeyException e) {
			Error("decryptAESKey(): Ungültig formatierter Schlüssel", e);
		} catch (IllegalBlockSizeException e) {
			Error("decryptAESKey(): Blockgroessen Fehler", e);
		} catch (BadPaddingException e) {
			Error("decryptAESKey(): Padding Fehler", e);
		}

	}

	/**
	 * 
	 * Entschlüsselt mit dem AES Schlüssel das Dokument und schreibt den
	 * entschlüsselten Inhalt in die Ausgabe Datei
	 * 
	 */

	public void decryptDokument() {

		try {

			// Cipher Instance erzeugen
			Cipher cipher = Cipher.getInstance("AES");

			SecretKeySpec specKey2 = new SecretKeySpec(aeskey, "AES");

			// Cipher Objekt initialisieren
			cipher.init(Cipher.DECRYPT_MODE, specKey2);

			// Dokument entschlüsseln
			decryptedDokument = cipher.doFinal(encryptedDokument);

			// String s3 = new String(encryptedBytes2);
			// System.out.println(s3);

			// Erstellt einen neuen Output Stream
			DataOutputStream out = new DataOutputStream((new FileOutputStream(
					dokument)));

			// Schreibt Daten in die Ausgabedatei
			out.write(decryptedDokument);

			// Schließen der Datei
			out.close();

		} catch (NoSuchAlgorithmException e) {
			Error("decryptDokument(): Keine Implementierung für AES", e);
		} catch (NoSuchPaddingException e) {
			Error("decryptDokument(): Keine Implementierung für das Padding", e);
		} catch (InvalidKeyException e) {
			Error("decryptDokument(): Ungültig formatierter Schlüssel", e);
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
	 * Diese Methode entschlüsselt die Signatur mit dem öffentlichen
	 * RSA-Schlüssel Und vergleicht in mit dem AES Schluessel
	 */

	private boolean verify() {

		try {

			// Nun wird die Signatur überprüft
			// als Erstes erzeugen wir das Signatur-Objekt
			Signature rsaSig = Signature.getInstance("SHA1withRSA");

			// zum Verifizieren benötigen wir den öffentlichen Schlüssel
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
