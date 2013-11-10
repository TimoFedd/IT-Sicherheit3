/**
 * 
 * RSAKeyCreation erzeugt ein 2024bit RSA Schl�sselpaar,
 * und speichert dies in den Dateien name.pub und name.prv.
 * 'name' wird dabei als Argument beim Aufruf �bergeben.
 * 
 * 
 * @author Timo Feddersen und Sergej Kimel
 * @version 1.0
 */

import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class RSAKeyCreation {

	// Der name des inhabers
	public String inhaber;

	// das Schl�sselpaar
	private KeyPair keyPair = null;
	
	//Output Steams
	DataOutputStream pub = null;
	DataOutputStream prv = null;
	


	public RSAKeyCreation(String inhaber) {
		this.inhaber = inhaber;
	}

	
	public static void main(String[] args) {

		RSAKeyCreation rc = new RSAKeyCreation(args[0]);
		rc.generateKeyPair();
		rc.writeKeyPair();
	}

	/**
	 * Diese Methode generiert ein neues Schl�sselpaar.
	 */
	public void generateKeyPair() {
		try {
			
			// als Algorithmus verwenden wir RSA
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			
			// mit gew�nschter Schl�ssell�nge initialisieren
			gen.initialize(2048);
			
			//Key Paar generieren
			keyPair = gen.generateKeyPair();
		

		} catch (NoSuchAlgorithmException ex) {
			Error("Es existiert kein KeyPairGenerator f�r RSA", ex);
		}
	}

	
	
	/**
	 * Diese Methode schreibt vom keypair, jeweils den privaten und public Teil
	 * in eine Datei. Die namen der Dateien sind:
	 * inhaber.pub (Public Schl�ssel) 
	 * inhaber.prv (privater Schl�ssel)
	 * 
	 * Inhaber wird als Parameter beim start des Programmes mit �bergeben
	 */

	public void writeKeyPair() {

		try {
			pub = new DataOutputStream((new FileOutputStream("C:\\Users\\Timo\\Desktop\\"+inhaber+".pub")));   //System.getProperty("user.dir"))\\Desktop\\"+inhaber+".prv"
			prv = new DataOutputStream((new FileOutputStream("C:\\Users\\Timo\\Desktop\\"+inhaber+".prv")));
		} catch (FileNotFoundException e) {
			Error("Fehler beim erstellen der Schl�ssel Datei ",e);
			e.printStackTrace();
		}
		
	
		try {
		
			//L�nge des Inhaber-Namens
			pub.writeInt(inhaber.length());
		    prv.writeInt(inhaber.length());
		    
		    
		    //inhaber Name
		    pub.write(inhaber.getBytes());
		    prv.write(inhaber.getBytes());
		
		    //L�nge des Schl�ssels und Schl�ssel an sich
		    PublicKey pubKey = keyPair.getPublic();
			byte[] pubKeyEnc = pubKey.getEncoded();
			pub.writeInt(pubKeyEnc.length);
			pub.write(pubKeyEnc);
			
			PrivateKey prvKey = keyPair.getPrivate();
			byte[] prvKeyEnc = prvKey.getEncoded();
		    prv.writeInt(prvKeyEnc.length);
		    prv.write(prvKeyEnc);
		    
		} catch (IOException e) {
			Error("Fehler beim erstellen der Schl�ssel Datei ",e);
			e.printStackTrace();
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
