package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;


public class CardApplet extends Applet implements ISO7816 {
private static final byte PRFE_CLA = (byte) 0xB0;
private static final byte CARD_SOFTWARE_VERSION = 0x0;
private static final byte CARD_TYPE = 0x0; // Regular card

private static final byte PIN_TRY_LIMIT = (byte) 4;
private static final byte PIN_SIZE = (byte) 6;

private static final short MAX_PETROL_CREDITS = (short) 10000;

// Incoming expected data block lengths
private static final short READ_INC_LEN = 4;
private static final short AUTH1_INC_LEN = 200; // TODO update this
private static final short AUTH2_INC_LEN = 200; // TODO update this

// Response lenghts
private static final short READ_RESP_LEN = 8;
private static final short AUTH1_RESP_LEN = 44;

// keys
private AESKey skey;

private ECPublicKey pukTMan;    // public key TMan
private ECPublicKey pukTChar;   // public key TChar
private ECPublicKey pukTCons;   // public key TCons
private ECPublicKey pukc;       // public key Card
private ECPrivateKey prkc;       // private key Card
private ECPublicKey purkc;      // private rekey Card
private ECPublicKey puks;       // Server certificate verification key
private KeyPair keyExchangeKP;  // Used for generating new random keys for a key exchange. Resulting key is used as AES session key.
private byte[] CCert;      // Server certificate verification key

// Key offsets in personalisation messages:
private static final short PUKTMAN_PERS_OFFSET = 0;
private static final short PUKTCHAR_PERS_OFFSET = 25;
private static final short PUKTCONS_PERS_OFFSET = 50;
private static final short PUKC_PERS_OFFSET = 75;
private static final short PRKC_PERS_OFFSET = 100;
private static final short PURKC_PERS_OFFSET = 125;
private static final short PUKS_PERS_OFFSET = 150;
private static final short CCERT_PERS_OFFSET = 175;
private static final short PIN_PERS_OFFSET = 195;

// Other offsets
private static final short SK_EXCH_PUBLIC_OFFSET = 4;
private static final short SK_EXCH_SIG1_OFFSET = SK_EXCH_PUBLIC OFFSET + AES_KEY_LENGTH;

// some lengths in bytes
private static final short EC_KEY_LENGTH = 25;
private static final short EC_CERT_LENGTH = 20;
private static final short AES_KEY_LENGTH = 16;
private static final short SIGN_LENGTH = 16;
private static final short NONCE_LENGTH = 8;

private KeyAgreement ECExch;
private Cipher AESCipher;
private Signature signature;
private RandomData random;

// Determines whether the card is in personalisation phase
private boolean manageable = true;

// Terminal information
private static final byte TERM_TYPE_CARD = 0x00;
private static final byte TERM_TYPE_TMAN = 0x01;
private static final byte TERM_TYPE_TCHAR = 0x02;
private static final byte TERM_TYPE_TCONS = 0x03;

private byte[] tInfo; // contains: 0: type; 1: software version; 2,3,4,5: terminal ID
private byte[] cID; // 4 bytes of card ID
private OwnerPIN pin;

private byte[] nonceC;
private byte[] nonceT;

private byte[] keyExchBuffer;
private byte[] sigBuffer;

private short petrolCredits;

private Object[] transactionLog;
private byte[] lastKnownTime;

// Keeps track of authentication and card state
// 0x00 unitialised
// 0x01 terminal authenticated as TMan
// 0x02 terminal authenticated as TChar
// 0x03 terminal authenticated as TCons
// 0x07 card has been revoked
// 0xff authentication initiated, session key exchanged
// User authentication is handled by the PIN class
private byte[] status; 


public CardApplet() {
    pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);

    status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);  
    keyExchBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
    sigBuffer = JCSystem.makeTransientByteArray((short) 30, JCSystem.CLEAR_ON_RESET);
    nonceC = JCSystem.makeTransientByteArray((short) NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);
    nonceT = JCSystem.makeTransientByteArray((short) NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);

    status[0] = 0x00; // unitialised

    skey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
    pukTMan  = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TMan
    pukTChar = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TChar
    pukTCons = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TCons
    pukc     = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // public key Card
    prkc     = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);       // private key Card
    purkc    = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);      // private rekey Card
    puks     = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // Server certificate verification key
    keyExchangeKP = new KeyPair(ALG_EC_FP, (short) 128); // Use 128 for easy match with AES 128

    CCert = new byte[SIGN_LENGTH];      // Server certificate verification key

    AESCihper = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD);
    ECExch = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    random = RandomData.getInstance(ALG_SECURE_RANDOM);

    cID = new byte[4];
    tInfo = JCSystem.makeTransientByteArray((short) 6, JCSystem.CLEAR_ON_RESET);
    
    petrolCredits = (short) 0;

    /*xy = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
    lastOp = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
    lastKeyWasDigit = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
    m = 0;*/
    register();
}


public static void install(byte[] buffer, short offset, byte length)
        throws SystemException {
    new CardApplet();
}

public boolean select() {
    status[0] = 0x00; // unitialised
    tInfo[0] = 0x000000; // sets entire array to 0 (4 bytes)

    return true;
}


public void process(APDU apdu) throws ISOException, APDUException {
    byte[] buffer = apdu.getBuffer();
    byte ins = buffer[OFFSET_INS];
    short lc_length;

    /* Ignore the APDU that selects this applet... */
    if (selectingApplet()) return;
    if (buffer[OFFSET_CLA] != PRFE_CLA) ISOException.throwIt(SW_CLA_NOT_SUPPORTED);


    switch (ins & 0xff) {
    case 0x00: 
        /*
         * READ instruction:
         * INS: 0x00
         * P1: Terminal Type 
         * P2: Terminal Software Version
         * Lc: should be READ_INC_LEN
         * Data: 32 bits of Terminal ID (READ_INC_LEN bytes)
         */

        if (!checkAndCopyTypeAndVersion(buffer)) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        // read the terminal ID into the apdu buffer
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) READ_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | READ_INC_LEN));
        }
        
        buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(buffer, (short) 0, tInfo, (short) 2, (short) READ_INC_LEN); 

        read(apdu, buffer);
        break;
    case 0x10:
        if (!checkAndCopyTypeAndVersion(buffer)) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        break;
    case 0x20:
        //charge
        break;
    case 0x30:
        //consume
        break;
    case 0x40:
        /* REVOKE instruction: 
		 * 
		 * This instruction can be executed at any authenticated terminal.
		 *
		 * INS: 0x40 
		 * P1: Terminal Software Version
		 * P2: Signing certificate
		 * Lc: 
		 * Data: 
		 *
		 
		if (((status[(short) 0] & 0xff) == 0x01) || ((status[(short) 0] & 0xff) == 0x02) || ((status[(short) 0] & 0xff) == 0x03) ) {
			tInfo[(short) 1] = buffer[OFFSET_P1];
			
			// TODO: check validity of certificate
			if (true) {
				revoke(apdu, buffer);
			}	
		} */
		
        break;
    case 0x50:
        /*
         * PERSONALISE instruction:
         *
         * Only allowed if terminal is authenticated as TMan, and manageable is still True.
         * 
         * Note: every EC key is 201 bits and every AES key is 128 bits,
         *
         * TODO: encrypt data for confidentiality? And send MAC? --> Assume TMan is in a secure environment so encryption not necessary?
         *
         * INS: 0x50
         * P1: Disable Personalisation after update
         * P2: Terminal Software Version 
         * Lc: 201 (bytes)
         * Data:
         *      25 bytes pukTMan
         *      25 bytes pukTChar
         *      25 bytes pukTCons
         *      25 bytes pukc
         *      25 bytes prkc
         *      25 bytes purkc
         *      25 bytes puks
         *      20 bytes CCert
         *      6 bytes of pin
         */
        if (manageable && (status[(short) 0] & 0xff) == 0x11) {
            manageable = (buffer[OFFSET_P1] & 0x01) == 0x01;
            tInfo[(short) 1] = buffer[OFFSET_P2];

            lc_length = apdu.setIncomingAndReceive();
            if (lc_length < (byte) 201) {
                ISOException.throwIt((short) (SW_WRONG_LENGTH | 201));
            }
         
            // Configuration is done in the specialised function:
            personalise(apdu, buffer);      
        }

        break;
    case 0x60:
        // rekey
        break;
    case 0xf0:
        //reset (connection)
        break;
    default:
        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
    }

        /* length check done for each instruction:
        length = apdu.setOutgoing();
        if (length < 5) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }
        buffer[0] = (m == 0) ? (byte) 0x00 : (byte) 0x01;
        Util.setShort(buffer, (short) 1, (short) 0);
        Util.setShort(buffer, (short) 3, xy[X]);
        apdu.setOutgoingLength((short) 5);
        apdu.sendBytes((short) 0, (short) 5);
        */
    }
    
    /**
     * Extracts the type and buffer values from the buffer.
     * If the values are plausible, it copies them to the tInfo array (information about last known terminal)
     * @param buffer byte[], the initial buffer of an incoming message. Assumes P1 and P2 to be at the OFFSET_P1 and OFFSET_P2 in buffer respectively.
     */
    private boolean checkAndCopyTypeAndVersion(byte[] buffer) {
        short type = (short) (buffer[OFFSET_P1] & 0xff);
        boolean plausible = type < (short) 4 || type == (short) 0xff; // The type should at least be in the right numeric range.

        // Terminal type should stay the same as before, otherwise the authentication fails.
        if (((status[(short) 0] & 0xff) > 0 && tInfo[(short) 0] != type) || !plausible) return false; 

        tInfo[(short) 0] = buffer[OFFSET_P1]; // terminal type
        tInfo[(short) 1] = buffer[OFFSET_P2]; // terminal software version 
        // TODO: The Terminal software version information is not currently used. Should we add this to the documentation?

        return true;
    }

    /**
     * Read some general data from the card.
     *
     * Sends card type; card software version; and card ID to the terminal.
     */ 
    private void read(APDU apdu, byte[] buffer) {
        // set the data transfer direction to outbound and to obtain the expected length of response
        short expectedLength = apdu.setOutgoing();
        
        if (expectedLength < (short) READ_RESP_LEN) ISOException.throwIt((short) (SW_WRONG_LENGTH | READ_RESP_LEN));
        
        // Return answer with some general data about the card:
        apdu.setOutgoingLength((byte) READ_RESP_LEN);
        
        buffer[(short) 0] = (byte) CARD_TYPE;
        buffer[(short) 1] = (byte) CARD_SOFTWARE_VERSION; 
        Util.arrayCopyNonAtomic(cID, (short) 0, buffer, (short) 2, (short) 4);
        Util.setShort(buffer, (short) 6, petrolCredits);
        
        apdu.sendBytes((short) 0, (short) READ_RESP_LEN);
    }

    private void authenticate(APDU apdu, byte[] buffer) {
        switch (status[(short) 0] & 0xff){
            case 0x00: // not authenticated, or in the process of authentication
                authenticatePhase1(apdu, buffer);
                break;
            case 0x0f:
         
                break;
            case 0x01: // terminal authenticated as TMan
            case 0x02: // terminal authenticated as TChar
            case 0x03: // terminal authenticated as TCons
               
                // The terminal is already authenticated, so nothing left to do. (reset handles other changes)
                ISOException.throwIt(SW_WARNING_STATE_UNCHANGED);
                break;
            default:
                // Crash:
                ISOException.throwIt(SW_UNKNOWN);
                break;
        }

    }

    /**
     * AUTHENTICATE instruction part 1
     * INS: 0x10
     * P1: Terminal Type
     * P2: Terminal Software version
     * Lc: 
     * Data:
     *      Assym Encrypted using prkt:
     *          terminal ID
     *          Terminal nonce (32 bits): nonceT
     *          AES session key (128 bits): skey
     *
     *
     * Data 2.0: TODO: update this in the design document
     *      4 bytes Terminal ID
     *      Public key exchange component, skeyT
     *      Signature over P1, P2, TID and skeyT with prkT
     */ 
    private void authenticatePhase1 (APDU apdu, byte[] buffer) {
        // First get and check the length of the data buffer:
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) AUTH1_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | AUTH1_INC_LEN));
        }

        buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(buffer, (short) 0, tInfo, (short) 2, (short) 4); 

        // Verify the signature over the message
        Util.arrayCopyNonAtomic(tInfo, (short) 0, sigBuffer, (short) 0, (short) 6);
        Util.arrayCopyNonAtomic(buffer, SK_EXCH_PUBLIC_OFFSET, sigBuffer, (short) 6, (short) AES_KEY_LENGTH)
        switch(tInfo[(short) 0]) { // Switch on card type
            case TERM_TYPE_TMAN:
                signature.init(pukTMan, MODE_VERIFY);
                break;
            case TERM_TYPE_TCHAR:
                signature.init(pukTChar, MODE_VERIFY);
                break;
            case TERM_TYPE_TCONS:
                signature.init(pukTCons, MODE_VERIFY);
                break;
            default: // unsupported type
                ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);                
        }
        
        if (!signature.verify(sigBuffer, (short) 0, (short) 6 + AES_KEY_LENGTH, buffer, SK_EXCH_SIG1_OFFSET, SIGN_LENGTH)) {
            ISOException.throwIt(SW_WRONG_DATA);
        }

        // Generate our part of the session key.
        keyExchangeKP.genKeyPair();
        ECExch.init(keyExchangeKP.getPrivate());
        ECExch.generateSecret(buffer, SK_EXCH_PUBLIC_OFFSET, AES_KEY_LENGTH, keyExchBuffer, (short) 0);

        // Convert keyExchBuffer to skey
        skey.setKey(keyExchBuffer, (short) 0);

        // Generate Card Nonce nonceC
        random.generateData(nonceC, (short) 0, (short) 8);
        
        /*
         *  Prepare response 
         *
         *  Contents:
         *  skeyC (16 bytes)
         *
         *  encrypted:
         *      cardID (4 bytes)
         *      nonceC (8 bytes)
         *      CCert (16 bytes)
         *      card message signature (16 bytes)
         */
        apdu.setOutgoingLength(AUTH1_RESP_LEN);

        keyExchangeKP.getPublic.getW(buffer, (short) 0); // first copy the public key exchange part

        // TODO encrypt all this and update buffer offsets
        Util.arrayCopyNonAtomic(cID, (short) 0, buffer, (short) 0, (short) 4); // card ID
        Util.arrayCopyNonAtomic(nonceC, (short) 0, buffer, (short) 4, (short) 8);
        Util.arrayCopyNonAtomic(CCert, (short) 0, buffer, (short) 12, (short) 16);
        
        signature.init(prkc, MODE_SIGN);
        signature.sign(buffer, (short) 0, (short) 28, buffer, (short) 28); // signature into buffer
        
        
        
        

        // TODO: generate random nonceC
        // TODO: encrypt cardID, nonceC, CCert, and signature with prkC over previous fields

        apdu.sendBytes((short) 0, AUTH1_RESP_LEN);
    }

    private void authenticatePhase2 (APDU apdu, byte[] buffer) {
        /*
         * AUTHENTICATE instruction part 2
         * Card received session key skey, and sent its credentials encrypted with skey.
         * INS: 0x10
         * P1: Terminal Type
         * P2: Terminal Software version
         * Lc: 
         * Data 2.0:
         *      4 bytes terminal ID
         *      
         */

        // First get and check the length of the data buffer:
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) AUTH1_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | AUTH1_INC_LEN));
        }




    }

    /**
     * Does the personalisation phase of the card. 
     *
     * Assumes that it was checked whether personalisation was allowed.
     * Assumes that the apdu buffer was the correct length.
     */
    private void personalise(APDU apdu, byte[] buffer) {
        buffer = apdu.getBuffer();
        
        pukTMan.setW(buffer, PUKTMAN_PERS_OFFSET, EC_KEY_LENGTH);
        pukTChar.setW(buffer, PUKTCHAR_PERS_OFFSET, EC_KEY_LENGTH);
        pukTCons.setW(buffer, PUKTCONS_PERS_OFFSET, EC_KEY_LENGTH);
        pukc.setW(buffer, PUKC_PERS_OFFSET, EC_KEY_LENGTH);
        prkc.setS(buffer, PRKC_PERS_OFFSET, EC_KEY_LENGTH);
        purkc.setW(buffer, PURKC_PERS_OFFSET, EC_KEY_LENGTH);
        puks.setW(buffer, PUKS_PERS_OFFSET, EC_KEY_LENGTH);

        Signature s = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        s.init(puks, Signature.MODE_VERIFY);
        
        if (true /* TODO: verify card ID and type card in CCert */) {
            for (short i = 0; i < EC_CERT_LENGTH; i++) {
                CCert[i] = buffer[(short) CCERT_PERS_OFFSET + i];
            }
        }

        pin.update(buffer, PIN_PERS_OFFSET, PIN_SIZE);

    }

	/**
	 * Revokes the validity of the card.
	 * 
	 * Assumes that the terminal and card are authenticated.
	 * Assumes that the validity of the revoking instruction certificate has been checked.
	 *
	private void revoke(APDU apdu, byte[] buffer) {
		buffer = apdu.getBuffer();
		
		status[0] = 0x07; // Card status is now revoked
	} */
}
