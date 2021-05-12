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
    private static final byte SOFTWARE_VERSION = (byte) 0;

    final static byte PRFE_CLA = (byte) 0xB0;

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
 
    // Pin
    private static final byte pintrylimit = (byte) 3;
    private static final byte pinsizelimit = (byte) 6;
    private OwnerPIN pin = OwnerPIN(pintrylimit, pinsizelimit);

    // Determines whether the card is in peronalisation phase
    private boolean managable = true;

    private byte[] tID;
    private byte[] cID;
    private short petrolCredits = (short) 0;

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
        skey = KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, LENGTH_AES_128, true);
        status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);  
        status[0] = 0x00; // unitialised

        pukTMan  = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TMan
        pukTChar = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TChar
        pukTCons = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TCons
        pukc     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true);       // public key Card
        prkc     = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);       // private key Card
        prrkc    = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);      // private rekey Card
        puks     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true);       // Server certificate verification key
        CCert;      // Server certificate verification key

        cID = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);
        tID = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);

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
        tID[0] = 0x0000; // sets entire array to 0 (4 bytes)

        return true;
    }
   

    public void process(APDU apdu) throws ISOException, APDUException {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        byte lc_length = apdu.getIncomingLength();

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) return;
        if (buffer[OFFSET_CLA] != PRFE_CLA) ISOException.throwIt(SW_CLA_NOT_SUPPORTED);


        switch (ins) {
        case 0x00: 
            /*
             * READ instruction:
             * INS: 0x00
             * P1: Terminal Type 
             * P2: Terminal Software Version
             * Lc: should be 4
             * Data: 32 bits of Terminal ID (4 bytes)
             */


            if (lc_length < (byte) 4) {
                ISOException.throwIt((short) (SW_WRONG_LENGTH | 4));
            }
            
            // TODO: check P1 and P2 for validity
            byte tType = buffer[OFFSET_P1];
            byte tSoftVersion = buffer[OFFSET_P2];
            
            // read the two bytes into the apdu buffer
            apdu.setIncomingAndReceive();
            buffer = apdu.getBuffer();

            tID[0] = buffer[(byte) 0];
            tID[1] = buffer[(byte) 1]; 
            tID[2] = buffer[(byte) 2]; 
            tID[3] = buffer[(byte) 3]; 

            read()
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
            //personalise
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

    /**
     * Buffer is assumed to be 3 bytes long
     */
    void read(byte* buffer) {
        // set the data transfer direction to outbound and to obtain the expected length of response
        lc_length = apdu.setOutgoing();
        
        if (lc_length < 2) ISOException.throwIt((short) (SW_WRONG_LENGTH | 2));
        
        /*
         * Return answer with some general data about the card:
         * INS: 0x00
         * P1: Card Type
         * P2: Card Software Version
         * LC: 2
         * Data: 16 bits of Card ID (2 bytes)
         */

        apdu.setOutgoingLength((byte) 4);
        
        buffer[0] = (byte) cID[0];
        buffer[1] = (byte) cID[1];
        buffer[2] = (byte) cID[2];
        buffer[3] = (byte) cID[3];
        
        apdu.sendBytes((short) 0, (short) 4);
    }
    
     
}
