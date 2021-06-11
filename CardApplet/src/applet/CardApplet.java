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
    private static final short PERS_INC_LEN0 = 228;
    private static final short PERS_INC_LEN1 = 172;
    private static final short READ_INC_LEN = 4;
    private static final short AUTH1_INC_LEN = 53;
    private static final short AUTH2_INC_LEN = 200; // TODO update this
    private static final short REVOKE_INC_LENGTH = 24; // Sign length + nonce length

    private static final short CHAR1_INC_LEN = 56;
    private static final short CHAR2_INC_LEN = 64;
    private static final short CONS1_INC_LENGTH = 8;
    private static final short CONS2_INC_LENGTH = 22;
    private static final short CONS3_INC_LENGTH = 22;


    // Response lenghts
    private static final short READ_RESP_LEN = 8;
    private static final short AUTH1_RESP_LEN = 80;

    private static final short CHAR1_RESP_LEN = 64;
    private static final short CHAR2_RESP_LEN = 112;
    private static final short CONS1_RESP_LEN = 22;
    private static final short CONS2_RESP_LEN = 22;
    private static final short CONS3_RESP_LEN = 32;


    // keys
    private AESKey skey;

    private ECPublicKey pukTMan;    // public key TMan
    private ECPublicKey pukTChar;   // public key TChar
    private ECPublicKey pukTCons;   // public key TCons
    private ECPublicKey pukc;       // public key Card
    private ECPrivateKey prkc;       // private key Card
    private ECPublicKey purkc;      // public rekey Card
    private ECPublicKey puks;       // Server certificate verification key
    private KeyPair keyExchangeKP;  // Used for generating new random keys for a key exchange. Resulting key is used as AES session key.

    private byte[] CCert;           // Server certificate signing CID, CType, and CCertExp
    private byte[] CCertExp;       // Expiration date of the certificate yymd 4 bytes
    private byte[] TCert;           // Server certificate signing TID, TType and TCertExp
    private byte[] TCertExp;        // Exp date of the certificate yymd, 4 bytes

    // Key offsets in personalisation messages:
    private static final short PUKTMAN_PERS_OFFSET = 5;
    private static final short PUKTCHAR_PERS_OFFSET = 56;
    private static final short PUKTCONS_PERS_OFFSET = 107;
    private static final short PUKC_PERS_OFFSET = 158;
    private static final short PRKC_PERS_OFFSET = 209;

    private static final short PURKC_PERS_OFFSET = 5;
    private static final short PUKS_PERS_OFFSET = 56;
    private static final short CCERT_PERS_OFFSET = 107;
    private static final short CCERT_EXP_PERS_OFFSET = 163;
    private static final short CID_PERS_OFFSET = 167;
    private static final short PIN_PERS_OFFSET = 171;

    // some lengths in bytes
    private static final short EC_PUB_KEY_LENGTH = 51;
    private static final short EC_PRIV_KEY_LENGTH = 24;
    private static final short EC_CERT_LENGTH = 56;
    private static final short AES_KEY_LENGTH = 16;
    private static final short SIGN_LENGTH = 16;
    private static final short DATE_LENGTH = 4;
    private static final short TIME_LENGTH = (short) (DATE_LENGTH + (short) 3);
    private static final short ID_LENGTH = 4;
    private static final short NONCE_LENGTH = 8;


    private KeyAgreement ECExch;
    private Cipher AESCipher;
    private Signature signature;
    private RandomData random;

    // Other offsets
    private static final short SK_EXCH_PUBLIC_OFFSET = 4;
    private static final short SK_EXCH_SIG1_OFFSET = SK_EXCH_PUBLIC_OFFSET + AES_KEY_LENGTH;

    // Determines whether the card is in personalisation phase
    private boolean manageable = true;

    // Terminal information
    private static final byte TERM_TYPE_CARD = 0x00;
    private static final byte[] TYPE_CARD_A = {(byte) 0x00};
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
    private short incomingPetrolQuota;

    private Object[] transactionLog;
    private byte[] lastKnownTime;
    private short tNum = 0;

    // Keeps track of authentication and card state
// 0x00 unitialised
// 0x01 terminal authenticated as TMan
// 0x02 terminal authenticated as TChar
// 0x03 terminal authenticated as TCons
// 0x04 card has been revoked
// 0x1. card is in a charging operation
// 0x0f authentication initiated, session key exchanged
// User authentication is handled by the PIN class
    private byte[] status;


    public CardApplet() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);

        status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        keyExchBuffer = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
        sigBuffer = JCSystem.makeTransientByteArray((short) 30, JCSystem.CLEAR_ON_RESET);
        nonceC = JCSystem.makeTransientByteArray((short) NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);
        nonceT = JCSystem.makeTransientByteArray((short) NONCE_LENGTH, JCSystem.CLEAR_ON_RESET);


        skey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);
        pukTMan = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TMan
        pukTChar = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TChar
        pukTCons = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true); // public key TCons
        pukc = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // public key Card
        prkc = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);       // private key Card
        purkc = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);      // private rekey Card
        puks = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);       // Server certificate verification key
        keyExchangeKP = new KeyPair(KeyPair.ALG_EC_FP, (short) 128); // Use 128 for easy match with AES 128

        TCert = JCSystem.makeTransientByteArray(EC_CERT_LENGTH, JCSystem.CLEAR_ON_RESET);
        TCertExp = JCSystem.makeTransientByteArray(DATE_LENGTH, JCSystem.CLEAR_ON_RESET);
        CCert = new byte[EC_CERT_LENGTH];      // Server certificate verification key
        CCertExp = new byte[DATE_LENGTH];   // Date, yymd
        lastKnownTime = new byte[TIME_LENGTH]; // Date and time, yymdhms


        AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ECExch = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        cID = new byte[4];
        tInfo = JCSystem.makeTransientByteArray((short) 6, JCSystem.CLEAR_ON_RESET);

        select(); // Reset status and tInfo

        petrolCredits = (short) 1;
        incomingPetrolQuota = (short) 0;

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
        status[0] = (byte) 0x00; // unitialised
        tInfo[0] = 0x00000000; // sets entire array to 0 (6 bytes)

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
                select(); // reset // TODO: Configure this as a better reset

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
                if (!checkAndCopyTypeAndVersion(buffer)) {
                    // reset status:
                    select();

                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                } else {
                    authenticate(apdu, buffer);
                }
                break;
            case 0x20:

                if (!checkAndCopyTypeAndVersion(buffer)) {
                    // reset status:
                    select();

                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                } else {
                    charge(apdu, buffer);
                }
                break;
            case 0x30:
                /** CONSUME instruction
                 *
                 * This instruction can be executed at authenticated TCons
                 *
                 * INS: 0x30
                 * P1: Terminal Type
                 * P2: Terminal Software Version
                 * Lc: CONSUME_INC_LENGTH
                 * Data: encryption of NonceT
                 */
/* TODO: sorry, I added this for some testing... (Also look at the break at the end. Cheers, David
        if(!checkAndCopyTypeAndVersion(buffer)) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        if(!checkAndCopyTypeAndVersion(buffer)) {
            //reset status:
            select();

            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
       // if(tInfo[0] != TERM_TYPE_TCONS) ISOException.throwIt()
        else{
            consume(apdu, buffer);
        }
 */


                break;


            case 0x40:
        /* REVOKE instruction:
		 *
		 * This instruction can be executed at any authenticated terminal.
		 *
		 * INS: 0x40
		 * P1: Terminal Type
		 * P2: Terminal Software Version
		 * Lc: should be REVOKE_INC_LENGTH
		 * Data: Signature over the revoke operation
		 *

		if (!checkAndCopyTypeAndVersion(buffer)) ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

		lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) REVOKE_LENGTH) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | REVOKE_INC_LENGTH));
        }

		buffer = apdu.getBuffer();

		if (((status[(short) 0] & 0xff) == 0x01) || ((status[(short) 0] & 0xff) == 0x02) || ((status[(short) 0] & 0xff) == 0x03) ) {
			tInfo[(short) 1] = buffer[OFFSET_P1];
			Util.arrayCopyNonAtomic(buffer, OFFSET_INS, sigBuffer, (short) 0, (short) 1); // Instruction byte
			Util.arrayCopyNonAtomic(cID, (short) 0, sigBuffer, (short) 1, (short) 4); // Card ID
			Util.arrayCopyNonAtomic(buffer, SIGN_LENGTH, sigBuffer, (short) 5, NONCE_LENGTH); // Nonce


			if (!verify(sigBuffer,(short) 0,(short) 13 ,buffer, (short) 0, SIGN_LENGTH)) {
				ISOException.throwIt(SW_WRONG_DATA);
			}
			else {
				revoke(apdu, buffer);
			}
		} */

                break;
            case 0x50:
                /*
                 * PERSONALISE instruction:
                 *
                 * Only allowed if manageable is still True.
                 *
                 * Note: every EC public key is 51 bytes; private key 24 bytes; and every AES key is 16 bytes.
                 *
                 * TODO: Send MAC? --> Assume TMan is in a secure environment so encryption not necessary?
                 *
                 * INS: 0x50
                 * P1: 0b00000bba : a) Disable Personalisation after update; b) 00: first personalisation instruction; 01: second personalisation instruction; 10: only set manageable;
                 * P2: Terminal Software Version
                 * Lc: PERS_INC_LEN (bytes)
                 * Data: (bb = 00)
                 *      51 bytes pukTMan
                 *      51 bytes pukTChar
                 *      51 bytes pukTCons
                 *      51 bytes pukc
                 *      24 bytes prkc
                 *
                 * Data: (bb = 01)
                 *      51 bytes purkc
                 *      51 bytes puks
                 *      56 bytes CCert
                 *      4 bytes CCertExp
                 *      6 bytes of pin
                 */
                if (manageable) {
                    manageable = (buffer[OFFSET_P1] & 0x01) == 0x01;
                    tInfo[(short) 1] = buffer[OFFSET_P2];

                    lc_length = apdu.setIncomingAndReceive();

                    // Configuration is done in the specialised function:
                    if ((buffer[OFFSET_P1] & 0x06) == 0x00) {
                        if (lc_length < (byte) PERS_INC_LEN0)
                            ISOException.throwIt((short) (SW_WRONG_LENGTH | PERS_INC_LEN0));
                        personalise0(apdu, buffer);
                    } else if ((buffer[OFFSET_P1] & 0x06) == 0x02) {
                        if (lc_length < (byte) PERS_INC_LEN1)
                            ISOException.throwIt((short) (SW_WRONG_LENGTH | PERS_INC_LEN1));
                        personalise1(apdu, buffer);
                    }
                } else {
                    System.out.println("not manageable");
                    ISOException.throwIt(SW_WARNING_STATE_UNCHANGED);
                }

                break;
            case 0x60:
                // rekey
                break;
            case 0xf0:
                //reset (connection)
                break;
            default:
                select(); // reset
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
     *
     * @param buffer byte[], the initial buffer of an incoming message. Assumes P1 and P2 to be at the OFFSET_P1 and OFFSET_P2 in buffer respectively.
     */
    private boolean checkAndCopyTypeAndVersion(byte[] buffer) {
        short type = (short) (buffer[OFFSET_P1] & 0xff);
        boolean plausible = type < (short) 4 || type == (short) 0xff; // The type should at least be in the right numeric range.
        short s = (short) (status[(short) 0] & 0xff);

        // Terminal type should stay the same as before, otherwise the authentication fails.
        if ((s != (short) 0xff && s > (short) 3) || (s > (short) 0 && tInfo[(short) 0] != type) || !plausible)
            return false;

        tInfo[(short) 0] = buffer[OFFSET_P1]; // terminal type
        tInfo[(short) 1] = buffer[OFFSET_P2]; // terminal software version
        // TODO: The Terminal software version information is not currently used. Should we add this to the documentation?

        return true;
    }

    /**
     * Increment nonce with 1
     */
    private void incNonce(byte[] nonce) {
        for (short i = (short) 7; i >= (short) 0; i--) {
            if (nonce[i] == 0xff) {
                nonce[i] = (byte) 0x00;
                // Continue looping to process carry
            } else {
                nonce[i] = (byte) (((short) (nonce[i] & 0xff) + 1) & 0xff); // increment byte with 1, unsigned
                break; // no carry so quit
            }
        }
        // Any remaining carry is just ignored.
    }

    /**
     * Convenience function for using the signature object.
     * <p>
     * Initialises in MODE_VERIFY using the key that fits the type of terminal that is currently selected.
     * Then it tries to verify the signature and buffer using the terminal key: throws ISOException.SW_SECURITY_STATUS_NOT_SATISFIED exception if signature fails.
     */
    private void termVerif(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) {
        switch (tInfo[(short) 0]) { // Switch on terminal type
            case TERM_TYPE_TMAN:
                signature.init(pukTMan, Signature.MODE_VERIFY);
                break;
            case TERM_TYPE_TCHAR:
                signature.init(pukTChar, Signature.MODE_VERIFY);
                break;
            case TERM_TYPE_TCONS:
                signature.init(pukTCons, Signature.MODE_VERIFY);
                break;
            default: // unsupported type
                select(); // reset
                ISOException.throwIt(SW_FUNC_NOT_SUPPORTED);
                break;
        }

        if (!signature.verify(inBuff, inOffset, inLength, sigBuff, sigOffset, SIGN_LENGTH)) {
            select(); // reset
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }


    private void checkExpDate(byte[] buff, short offset) {
        // Compare expiration date and the last known valid date: sanity check on dates
        // Check yymd: compare them as unsigned numbers; if any is lower, the expiration date is invalid. Throws data invalid.
        if ((short) (buff[offset] & 0xff) < (short) (lastKnownTime[(short) 0] & 0xff)
                || (short) (buff[(short) (offset + (short) 1)] & 0xff) < (short) (lastKnownTime[(short) 1] & 0xff)
                || (short) (buff[(short) (offset + (short) 2)] & 0xff) < (short) (lastKnownTime[(short) 2] & 0xff)
                || (short) (buff[(short) (offset + (short) 3)] & 0xff) < (short) (lastKnownTime[(short) 3] & 0xff)) {
            ISOException.throwIt(SW_DATA_INVALID);
        }
    }

    /**
     * Read some general data from the card.
     * <p>
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
        switch (status[(short) 0] & 0xff) {
            case 0x00: // not authenticated, or in the process of authentication
                authenticatePhase1(apdu, buffer);
                break;
            case 0x0f:
                authenticatePhase2(apdu, buffer);
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
     * Data 2.0:
     * 4 bytes Terminal ID
     * 16 bytes Public key exchange component, skeyT
     * 16 Signature over P1, P2, TID and skeyT with prkT
     */

    private void authenticatePhase1(APDU apdu, byte[] buffer) {
        // First get and check the length of the data buffer:
        short lc_length = apdu.setIncomingAndReceive();
        //if (lc_length < (byte) AUTH1_INC_LEN) {
        //    ISOException.throwIt((short) (SW_WRONG_LENGTH | AUTH1_INC_LEN));
        //}

        buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(buffer, (short) 5, tInfo, (short) 2, (short) 4);

        // Verify the signature over the message TODO: fix offsets and lengths
        Util.arrayCopyNonAtomic(tInfo, (short) 0, sigBuffer, (short) 0, (short) 6);
        Util.arrayCopyNonAtomic(buffer, SK_EXCH_PUBLIC_OFFSET, sigBuffer, (short) 6, (short) AES_KEY_LENGTH);
        //termVerif(sigBuffer, (short) 0, (short) ((short) 6 + AES_KEY_LENGTH), buffer, SK_EXCH_SIG1_OFFSET); TODO: reenable this; NOTE: keys may not be available during personalisation

        // Generate our part of the session key.
        keyExchangeKP.genKeyPair();
        ECExch.init(keyExchangeKP.getPrivate());
        ECExch.generateSecret(buffer, (short) 9, (short) 33, keyExchBuffer, (short) 0);

        // Convert keyExchBuffer to skey
        skey.setKey(keyExchBuffer, (short) 0);

        // Generate Card Nonce nonceC
        random.generateData(nonceC, (short) 0, (short) 8);

        /*
         *  Prepare response
         *
         *  Contents:
         *  skeyC (33 bytes)
         *
         *  encrypted:
         *      cardID (4 bytes) // padding to get to multiple of 64 bits aes block length
         *      nonceC (8 bytes) (nonce used as counter)
         *      CCert (16 bytes)
         *      CCertExp (4 bytes)
         *      card message signature (16 bytes)
         */
        apdu.setOutgoing();
        apdu.setOutgoingLength(AUTH1_RESP_LEN);

        ((ECPublicKey) keyExchangeKP.getPublic()).getW(buffer, (short) 0); // first copy the public key exchange part

        // Prepare the encryption buffer TODO: check offsets
        Util.arrayCopyNonAtomic(cID, (short) 0, buffer, (short) 33, (short) 4); // card ID
        Util.arrayCopyNonAtomic(nonceC, (short) 0, buffer, (short) 37, NONCE_LENGTH);
        Util.arrayCopyNonAtomic(CCert, (short) 0, buffer, (short) 49, SIGN_LENGTH);
        Util.arrayCopyNonAtomic(CCertExp, (short) 0, buffer, (short) 65, DATE_LENGTH);

        // only try this if prkc is initialised (authenticate may be called before personalisation phase
        if (prkc.isInitialized()) {
            signature.init(prkc, Signature.MODE_SIGN);
            System.out.printf("%d\n", signature.sign(buffer, (short) 0, (short) 52, buffer, (short) 52)); // signature into buffer
        }

        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
        AESCipher.doFinal(buffer, (short) 33, (short) 48, buffer, (short) 33); // encrypt in 4 blocks

        status[(short) 0] = (byte) 0x0f;
        apdu.sendBytes((short) 0, AUTH1_RESP_LEN);
    }

    private void authenticatePhase2(APDU apdu, byte[] buffer) {
        /*
         * AUTHENTICATE instruction part 2
         * Card received session key skey, and sent its credentials encrypted with skey.
         * INS: 0x10
         * P1: Terminal Type
         * P2: Terminal Software version
         * Lc:
         * Data 2.0:
         *      encrypted with skey:
         *          4 bytes terminal ID // padding to get to multiple of 64 bits, aes block length
         *          nonceT  (8 bytes) (nonce used as counter)
         *          nonceC' (8 bytes) (nonce used as counter)
         *          TCert  (16 bytes)
         *          TCertExp (4 bytes)
         *          terminal message signature (16 bytes) (over all plaintext data, incl. P1 and P2
         *
         */

        // First get and check the length of the data buffer:
        short lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) AUTH2_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | AUTH2_INC_LEN));
        }

        buffer = apdu.getBuffer();

        // Decrypt into buffer
        AESCipher.init(skey, Cipher.MODE_DECRYPT);
        AESCipher.doFinal(buffer, (short) 0, (short) 56, buffer, (short) 0);

        if (Util.arrayCompare(buffer, (short) 0, tInfo, (short) 2, (short) 4) != (byte) 0) {
            select(); // reset status
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Verify the signature over the message
        Util.arrayCopyNonAtomic(tInfo, (short) 0, sigBuffer, (short) 0, (short) 6);
        Util.arrayCopyNonAtomic(buffer, (short) 4, sigBuffer, (short) 6, (short) 36);
        termVerif(sigBuffer, (short) 0, (short) 42, buffer, (short) 40);

        incNonce(nonceC);
        if (Util.arrayCompare(nonceC, (short) 0, buffer, (short) 12, NONCE_LENGTH) != (byte) 0) {
            select();
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // All checks are done, now get the terminal nonce and verify the terminal certificate
        Util.arrayCopyNonAtomic(buffer, (short) 4, nonceT, (short) 0, NONCE_LENGTH);

        // Compare expiration date and the last known valid date: sanity check on dates
        checkExpDate(buffer, (short) 36);

        // Save TCert for charging operation
        Util.arrayCopy(buffer, (short) 20, TCert, (short) 0, SIGN_LENGTH);

        // copy TCert details into sigBuffer and verify signature. If it verifies, terminal is authenticated, so positive response can be returned :)
        Util.arrayCopyNonAtomic(tInfo, (short) 2, sigBuffer, (short) 0, (short) 4); // terminal ID
        sigBuffer[(short) 4] = tInfo[(short) 0]; // terminal type
        Util.arrayCopyNonAtomic(buffer, (short) 36, sigBuffer, (short) 5, (short) 4); // Expiration date of the certificate

        signature.init(puks, Signature.MODE_VERIFY);

        if (!signature.verify(sigBuffer, (short) 0, (short) 9, buffer, (short) 20, SIGN_LENGTH)) {
            select(); // reset
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        switch (tInfo[(short) 0]) {
            case TERM_TYPE_TMAN:
                status[(short) 0] = (byte) 0x01;
                break;
            case TERM_TYPE_TCHAR:
                status[(short) 0] = (byte) 0x02;
                break;
            case TERM_TYPE_TCONS:
                status[(short) 0] = (byte) 0x03;
                break;
            default:
                select(); // reset
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
        }

        // return terminal nonce (incremented and encrypted) to confirm authentication successful.
        incNonce(nonceT);
        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
        AESCipher.doFinal(nonceT, (short) 0, NONCE_LENGTH, buffer, (short) 0); // nonce is 8 bytes, so exactly one AES block of 64 bits

        apdu.setOutgoingAndSend((short) 0, (short) NONCE_LENGTH);
    }

    /**
     * Does the personalisation phase of the card.
     * <p>
     * Assumes that it was checked whether personalisation was allowed.
     * Assumes that the apdu buffer was the correct length.
     */
    private void personalise0(APDU apdu, byte[] buffer) {
        buffer = apdu.getBuffer();

        JCSystem.beginTransaction();
        pukTMan.setW(buffer, PUKTMAN_PERS_OFFSET, EC_PUB_KEY_LENGTH);
        pukTChar.setW(buffer, PUKTCHAR_PERS_OFFSET, EC_PUB_KEY_LENGTH);
        pukTCons.setW(buffer, PUKTCONS_PERS_OFFSET, EC_PUB_KEY_LENGTH);
        pukc.setW(buffer, PUKC_PERS_OFFSET, EC_PUB_KEY_LENGTH);
        prkc.setS(buffer, PRKC_PERS_OFFSET, EC_PRIV_KEY_LENGTH);

        JCSystem.commitTransaction();

        // Readback to ensure correct receiving, no bitrot
        apdu.setOutgoingAndSend((short) 5, PERS_INC_LEN0);
    }

    private void personalise1(APDU apdu, byte[] buffer) {
        buffer = apdu.getBuffer();

        JCSystem.beginTransaction();
        purkc.setW(buffer, PURKC_PERS_OFFSET, EC_PUB_KEY_LENGTH);
        puks.setW(buffer, PUKS_PERS_OFFSET, EC_PUB_KEY_LENGTH);

        // get CCert and its information
        Util.arrayCopy(buffer, CCERT_PERS_OFFSET, CCert, (short) 0, EC_CERT_LENGTH);
        Util.arrayCopy(buffer, CCERT_EXP_PERS_OFFSET, CCertExp, (short) 0, DATE_LENGTH);
        Util.arrayCopy(buffer, CID_PERS_OFFSET, cID, (short) 0, ID_LENGTH);

        // verify signature
        signature.init(puks, Signature.MODE_VERIFY);
        signature.update(cID, (short) 0, (short) 4);
        signature.update(TYPE_CARD_A, (short) 0, (short) 1);

        if (!signature.verify(CCertExp, (short) 0, (short) DATE_LENGTH, CCert, (short) 0, (short) 56)) {
            System.out.println("Signature not verifiable");
            JCSystem.abortTransaction();
            ISOException.throwIt(SW_WARNING_STATE_UNCHANGED);
        }

        pin.update(buffer, PIN_PERS_OFFSET, PIN_SIZE);
        JCSystem.commitTransaction();

        // Readback to ensure correct receiving, no bitrot
        apdu.setOutgoingAndSend((short) 5, PERS_INC_LEN1);
    }

    private void charge(APDU apdu, byte[] buffer) {
        switch (status[(short) 0] & 0xf0) {
            case 0x00:
                chargePhase1(apdu, buffer);
                break;
            case 0x10:
                chargePhase2(apdu, buffer);
                break;
            default:
                select();
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
        }
    }

    private void chargePhase1(APDU apdu, byte[] buffer) {
        /* Charge part 1
         *
         * This instruction can be executed at an authenticated charging terminal
         *
         * INS: 0x20
         * P1: Terminal Type
         * P2: Terminal Software Version
         * Lc: CHAR1_INC_LEN
         * Data: Signature over sequence nr
         */

        short lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) CHAR1_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | CHAR1_INC_LEN));
        }

        buffer = apdu.getBuffer();
        AESCipher.init(skey, Cipher.MODE_DECRYPT);
        AESCipher.doFinal(buffer, (short) 0, SIGN_LENGTH, nonceT, (short) 0);
        incNonce(nonceT);
        tNum = (short) (tNum + 1);

        short expectedLength = apdu.setOutgoing();
        if (expectedLength < (short) CHAR1_RESP_LEN) ISOException.throwIt((short) (SW_WRONG_LENGTH | CHAR1_RESP_LEN));
        apdu.setOutgoingLength((byte) CHAR1_RESP_LEN);

        Util.arrayCopy(cID, (short) 0, buffer, (short) 0, (short) 4);
        buffer[(short) 5] = (byte) (petrolCredits & 0xff);
        buffer[(short) 6] = (byte) ((petrolCredits >> 8) & 0xff);
        incNonce(nonceT);
        buffer[(short) 7] = (byte) (tNum & 0xff);
        buffer[(short) 8] = (byte) ((tNum >> 8) & 0xff);
        Util.arrayCopy(nonceT, (short) 0, buffer, (short) 8, (short) NONCE_LENGTH);
        // hash the data?
        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(buffer, (short) 0, (short) 16, buffer, (short) 8);

        apdu.setOutgoingAndSend((short) 0, (short) CHAR1_RESP_LEN);
        status[(short) 0] = (byte) (status[(short) 0] + 0x10);


    }

    private void chargePhase2(APDU apdu, byte[] buffer) {
        /* Charge part 2
         *
         * This instruction can be executed at an authenticated charging terminal
         *
         * INS: 0x20
         * P1: Terminal Type
         * P2: Terminal Software Version
         * Lc: CHAR2_INC_LEN
         * Data:
         * 		4 bytes of cID
         * 		2 bytes of new quota
         *      2 bytes of transaction number
         *		56 bytes of signature of the data
         */
        short lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) CHAR2_INC_LEN) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | CHAR2_INC_LEN));
        }

        buffer = apdu.getBuffer();
        Util.arrayCopy(buffer, (short) 0, sigBuffer, (short) 0, (short) 8);
        incNonce(nonceT);
        Util.arrayCopy(nonceT, (short) 0, sigBuffer, (short) 8, (short) NONCE_LENGTH);


        signature.init(skey, Signature.MODE_VERIFY);
        if (!signature.verify(sigBuffer, (short) 0, (short) 16, buffer, (short) 16, SIGN_LENGTH)) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);


        }
        petrolCredits = (short) (petrolCredits + buffer[(short) 5]);
        petrolCredits = (short) (petrolCredits + (buffer[(short) 6] << 8));


        short expectedLength = apdu.setOutgoing();
        if (expectedLength < (short) CHAR2_RESP_LEN) ISOException.throwIt((short) (SW_WRONG_LENGTH | CHAR2_RESP_LEN));
        apdu.setOutgoingLength((byte) CHAR2_RESP_LEN);

        Util.arrayCopy(cID, (short) 0, sigBuffer, (short) 0, (short) 4);
        Util.arrayCopy(TCert, (short) 0, sigBuffer, (short) 4, (short) SIGN_LENGTH);
        sigBuffer[(short) 20] = (byte) (petrolCredits & 0xff);
        sigBuffer[(short) 21] = (byte) ((petrolCredits >> 8) & 0xff);
        tNum = (short) (tNum + 1);
        sigBuffer[(short) 22] = (byte) (tNum & 0xff);
        sigBuffer[(short) 23] = (byte) ((tNum >> 8) & 0xff);

        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(sigBuffer, (short) 0, (short) 24, buffer, (short) 0);

        incNonce(nonceT);
        signature.sign(nonceT, (short) 0, NONCE_LENGTH, buffer, SIGN_LENGTH);

        apdu.setOutgoingAndSend((short) 0, (short) CHAR2_RESP_LEN);
        status[(short) 0] = (byte) (status[(short) 0] - 0x10);
    }

    private void consume(APDU apdu, byte[] buffer) {

        switch (status[(short) 0] & 0xf0) {
            case 0x00:
                consumePhase1(apdu, buffer);
                break;
            case 0x10:
                consumePhase2(apdu, buffer);
                break;
            case 0x20:
                consumePhase3(apdu, buffer);
            default:
                select();
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
        }
    }

    private void consumePhase1(APDU apdu, byte[] buffer) {
/*
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) CONS1_INC_LENGTH) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS1_INC_LENGTH));
        }

        buffer = apdu.getBuffer();

        // Decrypt into nonceT
        AESCipher.init(skey, Cipher.MODE_DECRYPT);
        AESCipher.doFinal(buffer, (short) 0, (short) 8, nonceT, (short) 0);

        //card sends back to the terminal:
//        card-id (4 bytes), petrolcredits (short), mac(hash{card-id, petrolCredits, incNonce(nonceT)}, skey)
//        -> signature length is 20 bytes


        nonceC = incNonce(nonceT);
        //hashedData = hash(card-id, petrolCredits, nonceC) -> hashing algorithm? SHA-1?

        //copy data to be hashed into sigbuffer
        Util.arrayCopyNonAtomic(cID, (short) 0, sigBuffer, (short) 0, (short) 4);
        Util.setShort(sigBuffer, (short) 4, petrolCredits);
        Util.arrayCopyNonAtomic(nonceC, (short) 0, sigBuffer, (short) 6, (short) NONCE_LENGTH);

        //hash the data with hashing algorithm
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // TODO: hash algorithm?
        byte[] hashedData = md.doFinal(sigBuffer);

        //construct mac and sign data
        signature.init(skey, MODE_SIGN);
        signature.sign(hashedData, 0, SIGN_LENGTH, sigBuffer, 0); //(should be 16 bytes?) so the total length of the data to send is 4+2+16 = 22 bytes of data

        short expectedLength = apdu.setOutgoing();

        if (expectedLength < (short) CONS1_RESP_LEN) ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS1_RESP_LEN));

        // Return answer with the given data:
        apdu.setOutgoingLength((byte) CONS1_RESP_LEN);

        // buffer[(short) 0] = (byte) CARD_TYPE;
        // buffer[(short) 1] = (byte) CARD_SOFTWARE_VERSION;
        Util.arrayCopyNonAtomic(cID, (short) 0, buffer, (short) 0, (short) 4);
        Util.setShort(buffer, (short) 4, petrolCredits);
        Util.arrayCopyNonAtomic(sigBuffer, (short) 0, buffer, (short) 6, SIGN_LENGTH);

        apdu.sendBytes((short) 0, (short) CONS1_RESP_LEN);
        status[(short) 0] = (byte) (status[(short) 0] + 0x10);
*/
    }

    private void consumePhase2(APDU apdu, byte[] buffer) {
/*
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) CONS2_INC_LENGTH) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS2_INC_LENGTH));
        }

        buffer = apdu.getBuffer();

        nonceT = incNonce(nonceC); // we dont send nonceT in the response from terminal, so increment it here
        nonceC = incNonce(nonceT); // sequence number to send in response is nonceC

        //offset in data buffer for the signature is 6 (card id and quota precede it)
        //data to verify is: cardID, nonceT, incomingPetrolQuota = 4, 8, 2 = 14 bytes

        incomingPetrolQuota = (short) (incomingPetrolQuota + buffer[(short) 5]);
        incomingPetrolQuota = (short) (incomingPetrolQuota + (buffer[(short) 6]) << 8);

        Util.arrayCopyNonAtomic(buffer, (short) 0, sigBuffer, (short) 0, (short) 4);
        Util.setShort(sigBuffer, (short) 4, incomingPetrolQuota);
        Util.arrayCopyNonAtomic(buffer, (short) 6, nonceT, (short) 0, (short) 8);

        signature.init(skey, Signature.MODE_VERIFY);
        boolean verified = signature.verify(sigBuffer, (short) 0, (short) 14, buffer, (short) 6, (short) 16);

        if (verified) {
            //if verified, we update the petrolcredits on the card, otherwise we skip this step
            petrolCredits = (short) petrolCredits - (short) incomingPetrolQuota;
        }

        //send response to terminal with: verified, mac(hash{card-id, verified, nonceC}, skey)
        //hash the data to send

        byte[] dataToHash = JCSystem.makeTransientByteArray((short) 14, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(cID, (short) 0, dataToHash, (short) 0, (short) 4);
        dataToHash[(short) 4] = (byte) verified;
        Util.arrayCopyNonAtomic(nonceC, (short) 0, dataToHash, (short) 5, (short) NONCE_LENGTH);

        MessageDigest md = MessageDigest.getInstance("SHA-1"); // TODO: hash algorithm?
        byte[] hashedData = md.doFinal(dataToHash);

        //sign hashed data
        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(hashedData, (short) 0, (short) 20, sigBuffer, (short) 0); //TODO: hash message length

        //verified = 1 byte, signature length 56?
        short expectedLength = apdu.setOutgoing();

        if (expectedLength < (short) CONS2_RESP_LEN) ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS2_RESP_LEN));

        // Return answer with the given data:
        apdu.setOutgoingLength((byte) CONS2_RESP_LEN);

        //  buffer[(short) 0] = (byte) CARD_TYPE;
        //  buffer[(short) 1] = (byte) CARD_SOFTWARE_VERSION;
        buffer[(short) 0] = (byte) verified;
        Util.arrayCopyNonAtomic(sigBuffer, (short) 0, buffer, (short) 1, (short) 56);  //TODO: change signature length

        apdu.sendBytes((short) 0, (short) CONS2_RESP_LEN);
        status[(short) 0] = (byte) (status[(short) 0] + 0x20);
*/
    }

    private void consumePhase3(APDU apdu, byte[] buffer) {
/*
        lc_length = apdu.setIncomingAndReceive();
        if (lc_length < (byte) CONS3_INC_LENGTH) {
            ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS3_INC_LENGTH));
        }

        buffer = apdu.getBuffer();

        nonceT = incNonce(nonceC);
        nonceC = incNonce(nonceT);

        ByteBuffer data = ByteBuffer.wrap(buffer);

        short incomingPetrolQuota = (short) data.getShort((short) 4); //read the short value after the card-id

        byte[] dataToVerify = JCSystem.makeTransientByteArray((short) 14, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(buffer, (short) 0, dataToVerify, (short) 0, (short) 4); //copy card-id
        Util.setShort(dataToVerify, (short) 4, incomingPetrolQuota); //set incoming petrol credit value
        Util.arrayCopyNonAtomic(buffer, (short) 6, nonceT, (short) 0, (short) 8); //sequence number

        mac = Signature.getInstance(MessageDigest.ALG_NULL, SIG_CIPHER_AES_CMAC_128, Cipher.PAD_ISO9797_M2);
        mac.init(skey, Signature.MODE_VERIFY);
        boolean verified = signature.verify(dataToVerify, (short) 0, (short) 14, data, (short) 6, (short) 16);

        if (verified) {
            if ((short) incomingPetrolQuota < (short) petrolCredits) {
                petrolCredits = petrolCredits + incomingPetrolQuota;
            }

            short expectedLength = apdu.setOutgoing();
            if (expectedLength < (short) CONS3_RESP_LEN)
                ISOException.throwIt((short) (SW_WRONG_LENGTH | CONS3_RESP_LEN));
            apdu.setOutgoingLength((byte) CONS3_RESP_LEN);

            //send to terminal: two signatures

            //mac(hash({card-id, TCert, petrolCredits, transaction_nr}, skey)
            //mac({nonceC}, skey)


            Util.arrayCopy(cID, (short) 0, sigBuffer, (short) 0, (short) 4);
            Util.arrayCopy(TCert, (short) 0, sigBuffer, (short) 4, (short) 16); //TODO: TCert length
            //   Util.setShort(sigBuffer, (short) 20, petrolCredits);
            sigBuffer[(short) 20] = (byte) (petrolCredits & 0xff);
            sigBuffer[(short) 21] = (byte) ((petrolCredits >> 8) & 0xff);
            (short) tNum = (short) (tNum + 1);
            //Util.setShort(sigBuffer, (short) 22, tNum);
            sigBuffer[(short) 22] = (byte) (tNum & 0xff);
            sigBuffer[(short) 23] = (byte) ((tNum >> 8) & 0xff);

            signature.init(skey, Signature.MODE_SIGN);
            signature.sign(sigBuffer, (short) 0, (short) 24, buffer, (short) 0);

            incNonce(nonceT);
            signature.sign(nonceT, (short) 0, NONCE_LENGTH, buffer, SIGN_LENGTH);

            apdu.setOutgoingAndSend((short) 0, (short) CONS3_RESP_LEN);
            status[(short) 0] = (byte) (status[(short) 0] - 0x20);

        }

        if (!verified) {
            select();
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
*/
    }

    /**
     * Revokes the validity of the card.
     *
     * Assumes that the terminal and card are authenticated.
     * Assumes that the validity of the revoking instruction certificate has been checked.
     *
     private void revoke(APDU apdu, byte[] buffer) {

     status[(short) 0] = (byte) 0x04; // Card status is now revoked
     } */

}