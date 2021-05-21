package applet;

import javacard.framework.*;
import javacard.security.*;


public class CardApplet extends Applet implements ISO7816 {
private static final byte PRFE_CLA = (byte) 0xB0;
private static final byte CARD_SOFTWARE_VERSION = 0x0;
private static final byte CARD_TYPE = 0x0; // Regular card

private static final byte PIN_TRY_LIMIT = (byte) 4;
private static final byte PIN_SIZE = (byte) 6;

private static final short MAX_PETROL_CREDITS = (short) 10000;

// keys
private AESKey skey;

private ECPublicKey pukTMan;    // public key TMan
private ECPublicKey pukTChar;   // public key TChar
private ECPublicKey pukTCons;   // public key TCons
private ECPublicKey pukc;       // public key Card
private ECPrivateKey prkc;       // private key Card
private ECPublicKey purkc;      // private rekey Card
private ECPublicKey puks;       // Server certificate verification key
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

private static final short EC_KEY_LENGTH = 25;
private static final short EC_CERT_LENGTH = 20;

// Determines whether the card is in personalisation phase
private boolean manageable = true;

private byte[] tInfo; // contains: 0: type; 1: software version; 2,3,4,5: terminal ID
private byte[] cID; // 4 bytes of card ID
private OwnerPIN pin;

private short petrolCredits;

private Object[] transactionLog;
private byte[] lastKnownTime;

// Keeps track of authentication and card state
// 0x00 unitialised
// 0x01 terminal authenticated as TMan
// 0x02 terminal authenticated as TChar
// 0x03 terminal authenticated as TCons
// 0x11 terminal authenticated as TMan and card authenticated
// 0x12 terminal authenticated as TChar and card authenticated
// 0x13 terminal authenticated as TCons and card authenticated
// User authentication is handled by the PIN class
private byte[] status; 


public CardApplet() {
    pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
    skey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
    status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);  
    status[0] = 0x00; // unitialised

    pukTMan  = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TMan
    pukTChar = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TChar
    pukTCons = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TCons
    pukc     = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // public key Card
    prkc     = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);       // private key Card
    purkc    = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);      // private rekey Card
    puks     = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // Server certificate verification key
    //CCert;      // Server certificate verification key

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
         * Lc: should be 4
         * Data: 32 bits of Terminal ID (4 bytes)
         */


                
        // TODO: check P1 and P2 for validity
        tInfo[(short) 0] = buffer[OFFSET_P1]; // terminal type
        tInfo[(short) 1] = buffer[OFFSET_P2]; // terminal software version
        
        // read the terminal ID into the apdu buffer
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) 4) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 4));
        }
        
        buffer = apdu.getBuffer();

        tInfo[(short) 2] = buffer[(byte) 0];
        tInfo[(short) 3] = buffer[(byte) 1]; 
        tInfo[(short) 4] = buffer[(byte) 2]; 
        tInfo[(short) 5] = buffer[(byte) 3]; 

        read(apdu, buffer);
        break;
    case 0x10:
        //authenticate()

        break;
    case 0x20:
        //charge
        break;
    case 0x30:
        //consume
        break;
    case 0x40:
        //revoke
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
        if (manageable && (status[0] & 0xff) == 0x11) {
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
        //revoke
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
     * Read some general data from the card.
     *
     * Sends card type; card software version; and card ID to the terminal.
     */ 
    private void read(APDU apdu, byte[] buffer) {
        // set the data transfer direction to outbound and to obtain the expected length of response
        short expectedLength = apdu.setOutgoing();
        
        if (expectedLength < (short) 6) ISOException.throwIt((short) (SW_WRONG_LENGTH | 6));
        
        /*
         * Return answer with some general data about the card:
         * INS: 0x00
         * P1: Card Type
         * P2: Card Software Version
         * LC: 2
         * Data: 16 bits of Card ID (2 bytes)
         */

        apdu.setOutgoingLength((byte) 6);
        
        buffer[(byte) 0] = (byte) CARD_TYPE;
        buffer[(byte) 1] = (byte) CARD_SOFTWARE_VERSION; 
        buffer[(byte) 2] = (byte) cID[(byte) 0];
        buffer[(byte) 3] = (byte) cID[(byte) 1];
        buffer[(byte) 4] = (byte) cID[(byte) 2];
        buffer[(byte) 5] = (byte) cID[(byte) 3];
        
        apdu.sendBytes((short) 0, (short) 5);
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
}
