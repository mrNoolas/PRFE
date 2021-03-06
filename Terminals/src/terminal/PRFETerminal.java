package terminal;

import javacard.security.*;
import javacard.framework.*;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacardx.crypto.*;

import java.lang.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

// imports for using JCardSim
//import com.licel.jcardsim.io.JavaxSmartCardInterface;
//import com.licel.jcardsim.smartcardio.JCardSimProvider;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

import applet.CardApplet;
import terminal.TerminalSwitch;

public abstract class PRFETerminal extends JPanel implements ActionListener {

    //private JavaxSmartCardInterface simulatorInterface; // SIM

    private static final long serialVersionUID = 1L;
    static final Font FONT = new Font("Monospaced", Font.BOLD, 24);
    static final String MSG_ERROR = "    -- error --     ";
    static final String MSG_DISABLED = " -- insert card --  ";
    static final String MSG_INVALID = " -- invalid card -- ";

    JTextField display;
    JPanel keypad;

    CardChannel applet;

    protected int pin = 0;

    // Data about this terminal:
    public byte T_TYPE;
    public byte T_SOFT_VERSION;
    public byte[] T_ID;

    // General constants
    static final byte PRFE_CLA = (byte) 0xb0;
    static final byte READ_INS = (byte) 0x00;
    static final byte AUTH_INS = (byte) 0x10;
    static final byte AUTH_BUY_INS = (byte) 0x70;
    static final byte REV_INS = (byte) 0x40;
    static final byte REKEY_INS = (byte) 0x60;

    // length constants
    static final short ID_LENGTH = 4;
    static final short NONCE_LENGTH = 8;
    static final short AES_KEY_LENGTH = 16;

    // keys
    protected KeyPair keyExchangeKP;
    protected KeyPair TMan;
    protected KeyPair TChar;
    protected KeyPair TCons;
    protected KeyPair Server; // Note: for this POC terminals also act as server.
    protected KeyPair Card;
    protected KeyPair ReCard;
    protected AESKey skey;

    // private ECPrivateKey prrkt;      // private rekey Terminal
    protected byte[] CCert;            // Server certificate verification key
    protected byte[] CCertExp = {(byte) 0x07, (byte) 0xe6, (byte) 0x01, (byte) 0x01}; // yymd: 2022-01-01

	  protected byte[] TCert = new byte[56];
	  protected byte[] TCertExp;

    protected KeyAgreement ECExch;
    protected Cipher AESCipher;
    protected Signature signature;
    protected RandomData random;

    // Session data:
    protected byte[] cardID;
    protected byte cardSoftVers;
    protected boolean authenticated = false;
    protected boolean buyerAuthenticated = false;
    protected byte cardType;
    protected int petrolQuota;
    protected byte[] nonceC;
    protected byte[] nonceT;

    public TerminalSwitch switchCallback;

    protected PRFETerminal() {
        skey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);

        keyExchangeKP = new KeyPair(KeyPair.ALG_EC_FP, (short) 128); // Use 128 for easy match with AES 128

        AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ECExch = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    abstract void buildGUI(JFrame parent);
    public abstract void actionPerformed(ActionEvent ae);

    void setCard(CardChannel applet) {
        this.applet = applet;
    }

    public void setEnabled(boolean b) {
        super.setEnabled(b);
        if (b) {
            setText(0);
        } else {
            setText(MSG_DISABLED);
        }
        Component[] keys = keypad.getComponents();
        for (int i = 0; i < keys.length; i++) {
            keys[i].setEnabled(b);

            if (keys[i] instanceof JButton && ((JButton) keys[i]).getText() == "Switch") {
                keys[i].setEnabled(!b); // enable switch key
            }
        }
    }

    void key(String txt) {
        if (txt == null) {
            keypad.add(new JLabel());
        } else {
            JButton button = new JButton(txt);
            button.addActionListener(this);
            keypad.add(button);
        }
    }

    String getText() {
        return display.getText();
    }

    void setText(String txt) {
        display.setText(txt);
    }

    void setText(int n) {
        setText(Integer.toString(n));
    }

    public void resetConnection(){
        cardID = new byte[] {0,0,0,0};
        cardSoftVers = 0;
        authenticated = false;
        buyerAuthenticated = false;
        cardType = 0;
        petrolQuota = 0;

        pin = 0;

        nonceC = new byte[] {0,0,0,0, 0,0,0,0};
        nonceT = new byte[] {0,0,0,0, 0,0,0,0};
    }


    /**
     * Increment nonce with 1
     */
    private void incNonce (byte[] nonce) {
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

    public int readCard(byte termType, byte termSoftVers, byte[] termID) {                                                 //default method, read information on card
        resetConnection();

        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU readCommand = new CommandAPDU(PRFE_CLA, READ_INS, termType, termSoftVers, termID, 0, ID_LENGTH, 8);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return 0;
        }

        System.out.println("PRFE Terminal");
        /*
         * process the response apdu
         *
         * data:
         *  1 byte card type
         *  1 byte card software version
         *  4 bytes card ID
         *  2 bytes petrolcredits
         */

        byte[] data = response.getData();


        cardType = data[0];
        cardSoftVers = data[1];

        System.arraycopy(data, 2, cardID, 0, 4);
        petrolQuota = (int) Util.getShort(data, (short) 6);

        System.out.printf("Read response from Card: Type: %x; Soft Vers: %x; ID: %x%x%x%x; Petrolquota: %x \n",
                cardType, cardSoftVers, cardID[0], cardID[1], cardID[2], cardID[3], petrolQuota);
        return (int) petrolQuota;
    }

    public String authenticate(byte termType, byte termSoftVers, byte[] termID) {
        // get the right keypair based on type
        KeyPair termKeys;
        switch (termType & 0xff) {
            case 0x01:
                termKeys = TMan;
                break;
            case 0x02:
                termKeys = TChar;
                break;
            case 0x03:
                termKeys = TCons;
                break;
            default:
                return "Error: terminal type unsupported for authentication";
        }

        // First initialise the session key
        resetConnection();
        byte[] buffer = new byte[93];
        keyExchangeKP.genKeyPair();

        System.arraycopy(termID, 0, buffer, 0, 4);
        ((ECPublicKey) keyExchangeKP.getPublic()).getW(buffer, (short) 4);

        // produce signature and add that to the buffer
        signature.init(termKeys.getPrivate(), Signature.MODE_SIGN);
        signature.update(new byte[] {termType, termSoftVers}, (short) 0, (short) 2);
        signature.sign(buffer, (short) 0, (short) 37, buffer, (short) 37);

        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU command = new CommandAPDU(PRFE_CLA, AUTH_INS, termType, termSoftVers, buffer, 0, 93, 161);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command);
        } catch (CardException e) {
            // TODO: do something with the exception
            resetConnection();

            System.out.println(e);
            return "Transmit Error";
        }

        /*
         * process the response apdu
         *
         * data:
         *  33 bytes skeyC
         *encrypted:
         *  4 bytes card ID
         *  8 bytes nonceC
         *  56 bytes CCert
         *  4 bytes CCertExp
         *  56 bytes card message signature
         */
        byte[] data = response.getBytes();
        if (data[0] == 0x62 && data[1] == 0) {
            System.out.println("Warning, terminal already authenticated");
            return "Warning, terminal already authenticated";
        } else if (data.length < 161) {
            // try rekeying and abort
            rekey(T_TYPE, T_SOFT_VERSION, false, false, false, false);
            return "Auth failed, attempted rekey";
        }

        data = response.getData();
        ECExch.init(keyExchangeKP.getPrivate());
        byte[] keyExchBuffer = new byte[20];
        ECExch.generateSecret(data, (short) 0, (short) 33, keyExchBuffer, (short) 0);

        skey.setKey(keyExchBuffer, (short) 0);

        // First decrypt the buffer
        AESCipher.init(skey, Cipher.MODE_DECRYPT);
        AESCipher.doFinal(data, (short) 33, (short) 128, data, (short) 33);

        // Then verify the message signature
        signature.init(Card.getPublic(), Signature.MODE_VERIFY);

        if (!signature.verify(data, (short) 0, (short) 105, data, (short) 105, (short) 56)) {
            resetConnection();
            return "Auth failed, return sig invalid";
        }

        // Then verify CCert
        // TODO: check that the CCert expiry date is in the future...
        signature.init(Server.getPublic(), Signature.MODE_VERIFY);
        byte[] CCert = new byte[9];
        System.arraycopy(data, 33, CCert, 0, 4);
        CCert[4] = (byte) 0;
        System.arraycopy(data, 101, CCert, 5, 4);

        if (!signature.verify(CCert, (short) 0, (short) 9, data, (short) 45, (short) 56)) {
            resetConnection();
            return "Auth failed, CCert invalid";
        }

        // Finally store verified data of the card
        System.arraycopy(data, 33, cardID, 0, 4);
        System.arraycopy(data, 37, nonceC, 0, 8);
        authenticated = true;

        // ================== Authentication Phase 2
        // Move forward with authenticating Terminal to card
        buffer = new byte[144];

        System.arraycopy(termID, 0, buffer, 0, 4);

        // First generate random 8 byte nonce
        nonceT = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonceT);

        System.arraycopy(nonceT, 0, buffer, 4, 8);

        // Then increment the card nonce
        incNonce(nonceC);
        System.arraycopy(nonceC, 0, buffer, 12, 8);

        // TODO: get from server, permanently store, and then retrieve TCert from storage here
        // Generate TCert & expiry date
        TCertExp = new byte[] {(byte) 0x07, (byte) 0xe5, (byte) 0x0c, (byte) 0x1f};

        signature.init(Server.getPrivate(), Signature.MODE_SIGN);
        signature.update(termID, (short) 0, (short) 4);
        signature.update(new byte[] {termType}, (short) 0, (short) 1); // Type termKeys
        signature.sign(TCertExp, (short) 0, (short) 4, TCert, (short) 0); // outputs 54, 55 or 56 bytes of signature data

        System.arraycopy(TCert, 0, buffer, 20, 56);
        System.arraycopy(TCertExp, 0, buffer, 76, 4);

        // sign message
        signature.init(termKeys.getPrivate(), Signature.MODE_SIGN);
        signature.update(new byte[] {termType, termSoftVers}, (short) 0, (short) 2);
        signature.sign(buffer, (short) 0, (short) 80, buffer, (short) 80);

        // AES block size is 128 bits so we pad using a block of 0's to the end.
        // encrypt message
        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
        AESCipher.doFinal(buffer, (short) 0, (short) 144, buffer, (short) 0);

        // and send it
        CommandAPDU command2 = new CommandAPDU(PRFE_CLA, AUTH_INS, termType, termSoftVers, buffer, 0, 144, 16);

        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command2);
        } catch (CardException e) {
            // TODO: do something with the exception
            resetConnection();

            System.out.println(e);
            return "Transmit Error";
        }


        /*
         * process the response apdu
         *
         * data:
         *  8 bytes nonceT
         */
        data = response.getData();
        AESCipher.init(skey, Cipher.MODE_DECRYPT);
        AESCipher.doFinal(data, (short) 0, (short) 16, data, (short) 0);

        if (!Arrays.equals(data, 0, 8, nonceC, 0, 8)) {
            resetConnection();
            return "NonceC returned incorrectly, authentication unsuccesful";
        }

        incNonce(nonceT);
        if (!Arrays.equals(data, 8, 16, nonceT, 0, 8)) {
            resetConnection();
            return "NonceT returned incorrectly, authentication unsuccesful";
        }

        System.out.println("Authentication Successful");
        return "Authentication Successful";
    }

    public String authenticateBuyer(byte termType, byte termSoftVers) {
        // get the right keypair based on type
        KeyPair termKeys;
        switch (termType & 0xff) {
            case 0x01:
                termKeys = TMan;
                break;
            case 0x02:
                termKeys = TChar;
                break;
            case 0x03:
                termKeys = TCons;
                break;
            default:
                return "Error: terminal type unsupported for authentication";
        }

        // First verify the entered pin for validity:
        if (pin > 999999 || pin < 0) {
            System.out.printf("Invalid pin: %d\n", pin);
            return "Invalid PIN";
        }

        byte[] buffer = new byte[16];
        buffer[8] = (byte) (pin / 100000);
        buffer[9] = (byte) ((pin / 10000) - (buffer[8] * 10));
        buffer[10] = (byte) ((pin / 1000) - (buffer[9] * 10) - (buffer[8] * 100));
        buffer[11] = (byte) ((pin / 100) - (buffer[10] * 10) - (buffer[9] * 100) - (buffer[8] * 1000));
        buffer[12] = (byte) ((pin / 10) - (buffer[11] * 10) - (buffer[10] * 100) - (buffer[9] * 1000) - (buffer[8] * 10000));
        buffer[13] = (byte) ((pin / 1) - (buffer[12] * 10) - (buffer[11] * 100) - (buffer[10] * 1000) - (buffer[9] * 10000) - (buffer[8] * 100000));

        incNonce(nonceT);
        Util.arrayCopy(nonceT, (short) 0, buffer, (short) 0, NONCE_LENGTH);

        // padded with two 0's at the end
        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
        AESCipher.doFinal(buffer, (short) 0, (short) 16, buffer, (short) 0);

        // reset internal pin
        pin = 0;

        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU command = new CommandAPDU(PRFE_CLA, AUTH_BUY_INS, termType, termSoftVers, buffer, 0, 16, 80);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command);
        } catch (CardException e) {
            // TODO: do something with the exception
            resetConnection();

            System.out.println(e);
            return "Transmit Error";
        }

        /*
         * process the response apdu
         *encrypted data:
         *  1 byte tttt 000v (t = tries remaining; v = valid/invalid)
         *  8 bytes nonceC
         *  8 bytes nonceT
         *  56 bytes card message signature
         *  7 bytes 0 padding
         */
        byte[] data = response.getBytes();
        if (data.length < 82) {
            // Something failed, abort
            System.out.printf("%x %x\n", data[0], data[1]);
            resetConnection();
            return "Auth error, please try again";
        }

        data = response.getData();
        AESCipher.init(skey, Cipher.MODE_DECRYPT);

        AESCipher.doFinal(data, (short) 0, (short) 80, data, (short) 0);
        signature.init(Card.getPublic(), Signature.MODE_VERIFY);

        incNonce(nonceC);
        if (!signature.verify(data, (short) 0, (short) 17, data, (short) 17, (short) 56)
                || !Arrays.equals(data, 1, 9, nonceC, 0, 8) || !Arrays.equals(data, 9, 17, nonceT, 0, 8)) {
            resetConnection();

            System.out.println("Card signature invalid");
            return "Auth error, please try again";
        }

        buyerAuthenticated = (data[0] & 0x0f) == 1;
        if (!buyerAuthenticated) {
            int tries = data[0] >> 4;
            System.out.printf("Wrong pin, %d tries remaining\n", tries);
            return "Wrong Pin!";
        }
        System.out.println("Authenticated Buyer Successfully");
        return "Authenticated Buyer Succesfully";
    }

    public String revoke(byte termType, byte termSoftVers) {
        byte[] revSign = switchCallback.revokeCard(cardID);

        if (authenticated) {
            CommandAPDU revokeCommand = new CommandAPDU(PRFE_CLA, REV_INS, termType, termSoftVers, revSign);
            ResponseAPDU response;

            try {
                response = applet.transmit(revokeCommand);
            } catch (CardException e) {
                // Card did not accept revocation, it is probably rogue.
                System.out.println(e);
                System.out.println("Revocation not accepted by card");
                return "Revocation not accepted by card";
            }

            byte[] data = response.getBytes();
            if ((data[0] & 0xff) == 0x90 && data[1] == 0) {
                System.out.println("Revocaton Succesful");
                return "Revocaton Succesful";
            }

            return "Revocation not accepted by card";
        } else {
            return "Must auth to send rev to the card!";
        }
    }

    /**
     * Generates new keys and distributes them to the card. If all rekey parameters are false, no new keys are generated,
     * but the card is still given a copy of the new keys.
     * @param rekeyCard
     * @param rekeyTMan
     * @param rekeyTChar
     * @param rekeyTCons
     * @return text to display to terminal user
     */
    public String rekey(byte termType, byte termSoftVers, boolean rekeyCard, boolean rekeyTMan, boolean rekeyTChar, boolean rekeyTCons) {
        switchCallback.requestRekey(rekeyCard, rekeyTMan, rekeyTChar, rekeyTCons);
        byte[] sign = switchCallback.getRekeySignature();

        byte[] buffer = new byte[228];
        ((ECPublicKey) TMan.getPublic()).getW(buffer, (short) 0);
        ((ECPublicKey) TChar.getPublic()).getW(buffer, (short) 51);
        ((ECPublicKey) TCons.getPublic()).getW(buffer, (short) 102);
        ((ECPublicKey) Card.getPublic()).getW(buffer, (short) 153);
        ((ECPrivateKey) Card.getPrivate()).getS(buffer, (short) 204);

        CommandAPDU command = new CommandAPDU(PRFE_CLA, REKEY_INS, termType, termSoftVers, sign, 0, 58, 58);
        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command);
        } catch (CardException e) {
            // TODO: do something with the exception
            resetConnection();
            System.out.println(e);
            return "Transmit Error";
        }

        byte[] data = response.getData();
        if (!Arrays.equals(data, 0, 58, sign, 0, 58)) {
            System.out.println("Readback incorrect");
            return "Readback incorrect for signature";
        }

        command = new CommandAPDU(PRFE_CLA, REKEY_INS, termType, termSoftVers, buffer, 0, 228, 0);
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command);
        } catch (CardException e) {
            // TODO: do something with the exception
            resetConnection();
            System.out.println(e);
            return "Transmit Error";
        }

        data = response.getBytes();
        if ((data[0] & 0xff) == 0x90 && data[1] == 0) {
            System.out.println("Rekeyed Succesfully");
            return "Rekeyed Succesfully";
        } 
        return "Rekey not accepted by card"; 
    }

    public abstract Dimension getPreferredSize();
}
