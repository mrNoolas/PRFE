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
    private byte[] ID;
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
        pukTChar = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_113, true); // public key TChar
        pukTCons = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_113, true); // public key TCons
        pukc     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_113, true);       // public key Card
        prkc     = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_113, true);       // private key Card
        prrkc    = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);      // private rekey Card
        puks     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true);       // Server certificate verification key
        CCert;      // Server certificate verification key

       

        /*xy = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
        lastOp = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        lastKeyWasDigit = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
        m = 0;*/
        register();
    }
    // original code: ===========================================================================

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new CardApplet();
    }

    public boolean select() {
        xy[X] = 0;
        xy[Y] = 0;
        lastOp[0] = (byte) '=';
        lastKeyWasDigit[0] = false;
        return true;
    }

    public void process(APDU apdu) throws ISOException, APDUException {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        short le = -1;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            return;
        }

        switch (ins) {
        case '0':
            digit((byte) 0);
            break;
        case '1':
            digit((byte) 1);
            break;
        case '2':
            digit((byte) 2);
            break;
        case '3':
            digit((byte) 3);
            break;
        case '4':
            digit((byte) 4);
            break;
        case '5':
            digit((byte) 5);
            break;
        case '6':
            digit((byte) 6);
            break;
        case '7':
            digit((byte) 7);
            break;
        case '8':
            digit((byte) 8);
            break;
        case '9':
            digit((byte) 9);
            break;
        case '+':
        case '-':
        case 'x':
        case ':':
        case '=':
            operator(ins);
            break;
        case 'S':
        case 'R':
        case 'M':
            mem(ins);
            break;
        case 'C':
            select();
            break;
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        le = apdu.setOutgoing();
        if (le < 5) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | 5));
        }
        buffer[0] = (m == 0) ? (byte) 0x00 : (byte) 0x01;
        Util.setShort(buffer, (short) 1, (short) 0);
        Util.setShort(buffer, (short) 3, xy[X]);
        apdu.setOutgoingLength((short) 5);
        apdu.sendBytes((short) 0, (short) 5);
    }

    void digit(byte d) {
        if (!lastKeyWasDigit[0]) {
            xy[Y] = xy[X];
            xy[X] = 0;
        }
        xy[X] = (short) ((short) (xy[X] * 10) + (short) (d & 0x00FF));
        lastKeyWasDigit[0] = true;
    }

    void operator(byte op) throws ISOException {
        switch (lastOp[0]) {
        case '+':
            xy[X] = (short) (xy[Y] + xy[X]);
            break;
        case '-':
            xy[X] = (short) (xy[Y] - xy[X]);
            break;
        case 'x':
            xy[X] = (short) (xy[Y] * xy[X]);
            break;
        case ':':
            if (xy[X] == 0) {
                ISOException.throwIt(SW_WRONG_DATA);
            }
            xy[X] = (short) (xy[Y] / xy[X]);
            break;
        default:
            break;
        }
        lastOp[0] = op;
        lastKeyWasDigit[0] = false;
    }

    void mem(byte op) {
        switch (op) {
        case 'S':
            m = xy[X];
            break;
        case 'R':
            xy[Y] = xy[X];
            xy[X] = m;
            break;
        case 'M':
            m += xy[X];
            break;
        }
        lastKeyWasDigit[0] = false;
    }
}
