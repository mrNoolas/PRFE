package applet;


/** * Sample Java Card Calculator applet which operates on signed shorts. Overflow * is silent.
*
* The instructions are the ASCII characters of the keypad keys: '0' - '9', '+',
* '-', * 'x', ':', '=', etc. This means that the terminal should send an APDU
* for each key pressed.
*
* Response APDU consists of 5 data bytes. First byte indicates whether the M
* register contains a non-zero value. The third and fourth bytes encode the X
* register (the signed short value to be displayed).
*
* The only non-transient field is m. This means that m is stored in EEPROM and
* all other memory used is RAM.
*
* @author Martijn Oostdijk (martijno@cs.kun.nl)
* @author Wojciech Mostowski (woj@cs.ru.nl)
*
*/

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
private ECPublicKey pukTMan;    // public key TMan
private ECPublicKey pukTChar;   // public key TChar
private ECPublicKey pukTCons;   // public key TCons
private ECPublicKey pukc;       // public key Card
private ECPrivateKey prkc;       // private key Card
private ECPrivateKey prrkc;      // private rekey Card
private ECPublicKey puks;       // Server certificate verification key
private byte[] CCert;      // Server certificate verification key

private AESKey skey;

private OwnerPIN pin;

// Determines whether the card is in personalisation phase
private boolean managable = true;

private byte[] tInfo; // contains: 0: type; 1: software version; 2,3,4,5: terminal ID
private byte[] cID; // 4 bytes of card ID

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
    prrkc    = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);      // private rekey Card
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
        tInfo[0] = buffer[OFFSET_P1]; // terminal type
        tInfo[1] = buffer[OFFSET_P2]; // terminal software version
        
        // read the terminal ID into the apdu buffer
        short lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) 4) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 4));
        }
        
        buffer = apdu.getBuffer();

        tInfo[2] = buffer[(byte) 0];
        tInfo[3] = buffer[(byte) 1]; 
        tInfo[4] = buffer[(byte) 2]; 
        tInfo[5] = buffer[(byte) 3]; 

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
        //personalise
        break;
    case 0x60:
        //revoke
        break;
    case 0x70:
        /*
         * PERSONALISE instruction:
         * INS: 0x70
         * P1: Terminal Software Version 
         * P2: 
         * Lc: 
         * Data:
         *      
         *
         */
         break;
    case 0x80:
        //rekey
        break;
    case 0x90:
        //personalise
        break;
    case 0xa0:
        //rekey
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

    private void read(APDU apdu, byte[] buffer) {
        // set the data transfer direction to outbound and to obtain the expected length of response
        short expectedLength = apdu.setOutgoing();
        
        if (expectedLength < 6) ISOException.throwIt((short) (SW_WRONG_LENGTH | 6));
        
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

/*
    private void personalise(byte[] buffer) {
        

    } 
 // keys
private ECPublicKey pukTMan;    // public key TMan
private ECPublicKey pukTChar;   // public key TChar
private ECPublicKey pukTCons;   // public key TCons
private ECPublicKey pukc;       // public key Card
private ECPrivateKey prkc;       // private key Card
private ECPrivateKey prrkc;      // private rekey Card
private ECPublicKey puks;       // Server certificate verification key
private byte[] CCert;      // Server certificate verification key

private AESKey skey;

private OwnerPIN pin = OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);

// Determines whether the card is in personalisation phase
private boolean managable = true;

private byte[] tInfo; // contains: 0: type; 1: software version; 2,3,4,5: terminal ID
private byte[] cID; // 4 bytes of card ID

private short petrolCredits;

private Object[] transactionLog;
private byte[] lastKnownTime;

 */  
     
}
