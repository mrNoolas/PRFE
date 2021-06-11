package terminal;

import javacard.security.*;
import javacard.framework.*;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacardx.crypto.*;

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

/**
 * Sample terminal for the Calculator applet.
 *
 * Code added for hooking in the simulator is marked with SIM
 *
 * @author Martijno
 * @author woj
 * @author Pim Vullers
 * @author erikpoll
 *
 */
public class TCons extends JPanel implements ActionListener {

    private byte[] tID;                    // ID of the terminal
    private byte TERMINAL_SOFTWARE_VERSION;

    private static final byte TERMINAL_TYPE = (byte) 0x3;




    //keys
    private KeyPair keyExchangeKP;
    private ECPublicKey pukc;             // public key Card
    private ECPrivateKey prkTCons;        // private key TCons
    private ECPublicKey purkTCons;        // public rekey TCons
    private ECPublicKey puks;             // Server certificate verification key
    private byte[] TCert;                 // Terminal certificate signed with prks

    private AESKey skey;                  // Session key

    //length constants
    private static final short ID_LENGTH = 4;
    private static final short NONCE_LENGTH = 8;
    private static final short TID_LENGTH     = 4;
    private static final short NONCET_LENGTH  = 8;
    private static final short AES_KEY_LENGTH = 16;

    private static final short SIGN_LENGTH = 56;


    private KeyAgreement ECExch;
    private Cipher AESCipher;
    private Signature signature;
    private RandomData random;

    //Instruction bytes
    private static final byte PRFE_CLA = (byte) 0xB0;
    private static final byte READ_INS = (byte) 0x00;
    private static final byte AUTH_INS = (byte) 0x10;
    private static final byte CONS_INS = (byte) 0x30;
    private static final byte REV_INS  = (byte) 0x40;


    // Data about this terminal:
    private static final byte T_TYPE = (byte) 0x03;
    private static final byte T_SOFT_VERSION = (byte) 0x00;
    private static final byte[] T_ID = {(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01};

    //private JavaxSmartCardInterface simulatorInterface; // SIM

    private static final long serialVersionUID = 1L;
    static final String TITLE = "Calculator";
    static final Font FONT = new Font("Monospaced", Font.BOLD, 24);
    static final Dimension PREFERRED_SIZE = new Dimension(300, 300);

    static final int DISPLAY_WIDTH = 20;
    static final String MSG_ERROR = "    -- error --     ";
    static final String MSG_DISABLED = " -- insert card --  ";
    static final String MSG_INVALID = " -- invalid card -- ";

    static final byte[] CALC_APPLET_AID = { (byte) 0x3B, (byte) 0x29,
            (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String CALC_APPLET_AID_string = "3B2963616C6301";

    static final CommandAPDU SELECT_APDU = new CommandAPDU(
    		(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, CALC_APPLET_AID);

    JTextField display;
    JPanel keypad;

    CardChannel applet;

    public TCons(JFrame parent) {
        skey      = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);   // session key

        pukc      = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);         // public key Card
        prkTCons  = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);        // private key TCons
        purkTCons = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);         // public rekey TCons
        puks      = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC, KeyBuilder.LENGTH_EC_F2M_193, true);         // certificate verification key
        keyExchangeKP = new KeyPair(KeyPair.ALG_EC_FP, (short) 128); // Use 128 for easy match with AES 128


        TCert = null;                                                                      // Terminal certificate containing
                                                                                           // ID, type of device and expiry date
        tID = new byte[TID_LENGTH];

        AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ECExch = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        //simulatorInterface = new JavaxSmartCardInterface(); // SIM
        buildGUI(parent);
        setEnabled(false);
        (new SimulatedCardThread()).start();
    }

    //functions

    public int readCard() {                                                 //default method, read information on card
        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU readCommand = new CommandAPDU(PRFE_CLA, READ_INS, T_TYPE, T_SOFT_VERSION, T_ID, 0, ID_LENGTH, 8);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return 0;
        }


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

        byte cardType = data[0];
        byte cardSoftVers = data[1];

        byte[] cardID = new byte[4];
        System.arraycopy(data, 2, cardID, 0, 4);

        short petrolQuota = Util.getShort(data, (short) 6);

        System.out.printf("Read response from Card: Type: %x; Soft Vers: %x; ID: %x%x%x%x; Petrolquota: %x \n",
                cardType, cardSoftVers, cardID[0], cardID[1], cardID[2], cardID[3], petrolQuota);
        return (int) petrolQuota;
    }

    public byte[] getCardData(ResponseAPDU response){
        byte[] data = response.getData();
        return data;
    }

//    public byte[] getCardID(byte[] data){
//        byte[] cardID = new byte[4];
//        Util.arrayCopy(data, (short) 0, cardID, (short) 0, (short) 4);
//        return cardID;
//    }

    public short getPetrolCredit(byte[] data){
        //get petrol credit from the card
        //
        //
        return 0;
    };

    /*public void authenticateCard(){                                                         //authenticate card before we perform any transactions
        //generate nonceT
       // byte[] nonceT = generateNonce();
        //data to be sent in the apdu: tID, skeyT, sign({tID, skeyT}, prkTCons)
        //tID (= 4 bytes) + skeyT (= 16 bytes), sign tID and skeyT with prkTCons

        //skeyT is public part of skey, use keypair generator to generate this and the secret part of skeyT?
        keyExchangeKP.genKeyPair();
        byte[] skeyT = keyExchangeKP.getPublic().getEncoded();
        byte[] skeyTPriv = keyExchangeKP.getPrivate().getEncoded();

        byte[] dataToSign = new byte[20];
        Util.arrayCopy(tID, (short) 0, dataToSign, (short) 0, (short) 4);
        Util.arraycopy(skeyT, (short) 0, dataToSign, (short) 4, (short) 16);
        byte[] signedData = sign(dataToSign);

        byte[] message = new byte[20 + signedData.length];
        Util.arrayCopy(tID, (short) 0, message, (short) 0, (short) 4);
        Util.arrayCopy(skeyT, (short) 0, message, (short) 4, (short) AES_KEY_LENGTH);
        Util.arrayCopy(signedData, (short) 0, message, (short) 20, (short) signedData.length);

        //construct apdu with AUTH_INS and message as data
        CommandAPDU authenticateCommand = new CommandAPDU((byte) PRFE_CLA, (byte)AUTH_INS, (byte)TERMINAL_TYPE,
                (byte)TERMINAL_SOFTWARE_VERSION, message);
        ResponseAPDU response = applet.transmit(authenticateCommand);
        //response data: -> response is length 80?
        //enc(sign({cID, nonceC, CCert, CCertExp}, pukc), skey);
        //decrypt with skey
        byte[] cardData = decryptAES(response.getData(), skey);
        signature.init(pukc, Signature.MODE_VERIFY);
        signature.verify(cardData);


        //TODO: process data from card, decrypt, and verify CCert

        //data contains cardID, nonceC, CCert.
        //response from card contains CCert, which needs to be verified using puks
        //if CCert does not verify, send reset to card.
        //if card is authenticated, authenticate terminal.


        return;
    };


    public void authenticateBuyer() {               //authenticate buyer before we perform any transactions
        //TODO: implement authenticate buyer
        /*buyer enters pin
        send pin to card
        if pin not verified, try new pin
        if pin tries remaining = 0 and pin != verified, revoke card and exit.
         */
    //}

    public byte[] generateNonce(){
        //generate a 32 bit random nonce
        byte[] nonce = new byte[NONCET_LENGTH];
        return random.nextBytes(nonce);
    };

    public void consumeQuota(){                                                        //use an amount of petrol quota on the card
        //TODO: implement method to update the quota on the card
        //send sequence number to card to start the consumption transaction
        byte[] nonceT = generateNonce();
        byte[] sigBuffer = new byte[2*SIGN_LENGTH];

        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(nonceT, (short) 0, (short) 8, sigBuffer, (short) 0);
        CommandAPDU consumeCommand = new CommandAPDU(PRFE_CLA, CONS_INS, T_TYPE, T_SOFT_VERSION, sigBuffer);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return 0;
        }

        //verify response
        byte[] data = response.getData();
        //data = card-id, quota, signedData
        byte[] cardID = new byte[4];
        Util.arrayCopy(data, 0, 4, cardID, 0, 4);
        short petrolQuotaOnCard = Util.getShort(data, (short) 4);
        byte[] nonceC = incNonce(nonceT); //sequence nr + 1

        System.arrayCopy(cardID, 0, sigBuffer, 0, 4);
        Util.setShort(sigBuffer, (short) 4, petrolQuotaOnCard);
        System.arrayCopy(nonceC, 0, sigBuffer, 6, NONCET_LENGTH);

        signature.init(skey, Signature.MODE_VERIFY);
        if (!signature.verify(sigBuffer, 0, 14, data, 6, SIGN_LENGTH)) {
            throw new Exception("Signature invalid");

        }

        short amount = 0;
        //amount = entered by the buyer
        //TODO: read input and put this value into short amount

        //buffer for key listener and read in from that
        //card has quota balance
        if (petrolQuotaOnCard - amount < 0){
            throw new Exception("Invalid amount");
        }
        //if quota on card - amount < 0 : exit
        short wantedPetrol = petrolQuotaOnCard - (short) amount;
        nonceT = incNonce(nonceC); //sequence nr + 2
        byte[] dataBuffer = new byte[14]
        System.arrayCopy(cardID, 0, dataBuffer, 0, 4);
        Util.setShort(dataBuffer, 4, wantedPetrol);
        System.arrayCopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);
        signature.init(skey, Signature.MODE_SIGN);
        signature.update(dataBuffer);
        byte[] signedData = signature.sign();
        System.arrayCopy(signedData, 0, sigBuffer, 6, SIGN_LENGTH);
        CommandAPDU cons2Command = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int) TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, sigBuffer);

        try {
            ResponseAPDU response = applet.transmit(cons2Command);
        } catch (CardException e) {
            System.out.println(e);
            return 0;
        }
        nonceC = incNonce(nonceT); //sequence nr + 3
        nonceT = incNonce(nonceC); //sequence nr + 4
        byte[] responseData = response.getData();
        if(responseData[0] == (byte) 1){
            setMaxGas(wantedPetrol);
            if(getGasUsed() < wantedPetrol){

                short updatedQuota = wantedPetrol - getGasUsed();

                System.arrayCopy(cardID, 0, dataBuffer, 0, 4);
                Util.setShort(dataBuffer, 4,  updatedQuota);
                System.arrayCopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);

                signature.init(skey, Signature.MODE_SIGN);
                signature.update(dataBuffer);
                signedData = signature.sign();

                System.arrayCopy(cardID, 0, sigBuffer, 0, 4);
                Util.setShort(sigBuffer, 4, updatedQuota);
                System.arrayCopy(signedData, 0, sigBuffer, 6, SIGN_LENGTH);

                CommandAPDU cons3Command = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int) TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, sigBuffer);

                try {
                    ResponseAPDU response = applet.transmit(cons3Command);
                } catch (CardException e) {
                    System.out.println(e);
                    return 0;
                }
            }
        }

    };

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

    void setMaxGas(short wantedPetrol){
        return;
    };                                                                             //set the max amount of gas available to the buyer based on the quota on card (a short?)

    short getGasUsed(short maxGas, short amount){
        //TODO: implement method to update amount of gas used by buyer
        for(i = 0, i < maxGas, i++){

        }

    };                                                                                          //return the amount of gas dispensed


    public byte[] sign(byte[] data){
        signature.initSign(prkTCons);
        signature.update(data);
        byte[] signedData = signature.sign();
        return signedData;
    };

    public byte[] hash(byte[] data){
        //create message digest using a certain hash algorithm
        MessageDigest md = MessageDigest.getInstance(""); //TODO: decide hash algorithm?
        //use hash to hash the data
        md.update(data);
        //generate the hash of the data
        byte[] hash = md.digest();
        return hash;

    };

    public byte[] mac(byte[] data, AESKey key){                                                                              //mac code for sending data between card and terminal, using java.crypto.Mac object?
        //create mac object
        Mac mac = Mac.getInstance("SHA-1"); //TODO: algorithm for mac?
        //initialise the Mac object with the skey
        mac.init(key);
        //compute mac
        byte[] macResult = mac.doFinal(data);
        return macResult;
    };

    public boolean verify(byte[] signedData, byte[] key){
        signature.init(key, Signature.MODE_VERIFY);
        signature.verify(signedData);
        return true;
    };

    public byte[] encryptAES(byte[] data, AESKey key){
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data);
        return encryptedData;
    }

    public byte[] decryptAES(byte[] encryptedMessage, AESKey key){
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return decryptedMessage;
    }


    //original terminal code starts here

    void buildGUI(JFrame parent) {
        setLayout(new BorderLayout());
        display = new JTextField(DISPLAY_WIDTH);
        display.setHorizontalAlignment(JTextField.RIGHT);
        display.setEditable(false);
        display.setFont(FONT);
        display.setBackground(Color.darkGray);
        display.setForeground(Color.green);
        add(display, BorderLayout.NORTH);
        keypad = new JPanel(new GridLayout(5, 5));
        key("Read");
        key("Authenticate");
        key(null);
        key(null);
        key("C");
        key("7");
        key("8");
        key("9");
        key(":");
        key("ST");
        key("4");
        key("5");
        key("6");
        key("x");
        key("RM");
        key("1");
        key("2");
        key("3");
        key("-");
        key("M+");
        key("0");
        key(null);
        key(null);
        key("+");
        key("=");
        add(keypad, BorderLayout.CENTER);
        parent.addWindowListener(new CloseEventListener());
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
            setMemory(data[0] == 0x01);
        }
    }

    void setMemory(boolean b) {
        String txt = getText();
        int l = txt.length();
        if (l < DISPLAY_WIDTH) {
            for (int i = 0; i < (DISPLAY_WIDTH - l); i++) {
                txt = " " + txt;
            }
            txt = (b ? "M" : " ") + txt;
            setText(txt);
        }
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
        }
    }


    /* Connect the terminal with a simulated smartcard JCardSim
     */
    class SimulatedCardThread extends Thread {
        public void run() {
          // Obtain a CardTerminal
          CardTerminals cardTerminals = CardTerminalSimulator.terminals("My terminal 1");
          CardTerminal terminal1 = cardTerminals.getTerminal("My terminal 1");

          // Create simulator and install applet
          CardSimulator simulator = new CardSimulator();
          AID cardAppletAID = new AID(CALC_APPLET_AID,(byte)0,(byte)7);
          simulator.installApplet(cardAppletAID, CardApplet.class);

          // Insert Card into "My terminal 1"
          simulator.assignToTerminal(terminal1);

          try {
            Card card = terminal1.connect("*");

    	    applet = card.getBasicChannel();
    	    ResponseAPDU resp = applet.transmit(SELECT_APDU);
    	    if (resp.getSW() != 0x9000) {
    	      throw new Exception("Select failed");
    	    }
    	    setText(sendKey((byte) '='));
    	    setEnabled(true);
          } catch (Exception e) {
              System.err.println("Card status problem!");
          }
      }
    }

    public void actionPerformed(ActionEvent ae) {
        try {
            Object src = ae.getSource();
            if (src instanceof JButton) {
                char c = ((JButton) src).getText().charAt(0);

                switch(c) {
                    case 'R': // read
                        setText(readCard());
                        break;
                    case 'A': // authenticate
                        //setText(authenticate());
                        break;
                    default:
                        setText(sendKey((byte) c));
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(MSG_ERROR);
        }
    }

    class CloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            System.exit(0);
        }
    }

    public ResponseAPDU sendKey(byte ins) {
        CommandAPDU apdu = new CommandAPDU(0, ins, 0, 0, 5);
        try {
			return applet.transmit(apdu);
		} catch (CardException e) {
			return null;
		}
    }

    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

    public static void main(String[] arg) {
        JFrame frame = new JFrame(TITLE);
        Container c = frame.getContentPane();
        TCons panel = new TCons(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
