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

    // Data about this terminal:
    public byte T_TYPE;
    public byte T_SOFT_VERSION;
    public byte[] T_ID;

    // General constants
    static final byte PRFE_CLA = (byte) 0xb0;
    static final byte READ_INS = (byte) 0x00;
    static final byte AUTH_INS = (byte) 0x10;

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

    protected KeyAgreement ECExch;
    protected Cipher AESCipher;
    protected Signature signature;
    protected RandomData random;

    // Session data:
    protected byte[] cardID;
    protected byte cardSoftVers;
    protected boolean cardAuthenticated = false;
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

    void setText(ResponseAPDU apdu) {
        byte[] data = apdu.getData();
        int sw = apdu.getSW();
        if (sw != 0x9000 || data.length < 5) {
            setText(MSG_ERROR);
        } else {
            setText((short) (((data[3] & 0x000000FF) << 8) | (data[4] & 0x000000FF)));
        }
    }

    private void resetConnection(){
        cardID = new byte[] {0,0,0,0};
        cardSoftVers = 0;
        cardAuthenticated = false;
        cardType = 0;
        petrolQuota = 0;
        
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
        cardAuthenticated = true;
        
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
        byte[] TCertExp = new byte[] {(byte) 0x07, (byte) 0xe5, (byte) 0x0c, (byte) 0x1f};

        signature.init(Server.getPrivate(), Signature.MODE_SIGN);
        signature.update(termID, (short) 0, (short) 4);
        signature.update(new byte[] {termType}, (short) 0, (short) 1); // Type termKeys
        signature.sign(TCertExp, (short) 0, (short) 4, buffer, (short) 20); // outputs 54, 55 or 56 bytes of signature data
        System.arraycopy(TCertExp, 0, buffer, 76, 4);

        // sign message
        signature.init(termKeys.getPrivate(), Signature.MODE_SIGN);
        signature.update(new byte[] {termType, termSoftVers}, (short) 0, (short) 2);
        signature.sign(buffer, (short) 0, (short) 80, buffer, (short) 80);

        /*
         * For some reason AES does not want to encrypt 17 (or 19) blocks, 
         * so we add a block of 0's to the end... We do not know why :(
         */
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

    public abstract Dimension getPreferredSize();
}
