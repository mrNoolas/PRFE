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
public class TMan extends JPanel implements ActionListener {

    //private JavaxSmartCardInterface simulatorInterface; // SIM

    private static final long serialVersionUID = 1L;
    static final String TITLE = "Management Terminal";
    static final Font FONT = new Font("Monospaced", Font.BOLD, 24);
    static final Dimension PREFERRED_SIZE = new Dimension(900, 300);

    static final int DISPLAY_WIDTH = 60;
    static final String MSG_ERROR = "    -- error --     ";
    static final String MSG_DISABLED = " -- insert card --  ";
    static final String MSG_INVALID = " -- invalid card -- ";

    static final byte[] CALC_APPLET_AID = { (byte) 0x3B, (byte) 0x29, (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String CALC_APPLET_AID_string = "3B2963616C6301";

    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, CALC_APPLET_AID);

    JTextField display;
    JPanel keypad;

    CardChannel applet;

    // General constants
    private static final byte PRFE_CLA = (byte) 0xb0;
    private static final byte READ_INS = (byte) 0x00;
    private static final byte AUTH_INS = (byte) 0x10;
    private static final byte PERS_INS = (byte) 0x50;

    // length constants
    private static final short ID_LENGTH = 4;
    private static final short NONCE_LENGTH = 8;
    private static final short AES_KEY_LENGTH = 16;

    // Data about this terminal:
    private static final byte T_TYPE = (byte) 0x01;
    private static final byte T_SOFT_VERSION = (byte) 0x00;
    private static final byte[] T_ID = {(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01};


    // keys
    private KeyPair keyExchangeKP;
    private KeyPair TMan;
    private KeyPair TChar;
    private KeyPair TCons;
    private KeyPair Server; // Note: for this POC terminals also act as server.
    private KeyPair Card;
    private KeyPair ReCard;
    private AESKey skey;

    // private ECPrivateKey prrkt;      // private rekey Terminal
    private byte[] CCert;            // Server certificate verification key
    private byte[] CCertExp = {(byte) 0x07, (byte) 0xe6, (byte) 0x01, (byte) 0x01}; // yymd: 2022-01-01

    private KeyAgreement ECExch;
    private Cipher AESCipher;
    private Signature signature;
    private RandomData random;

    // Session data:
    private byte[] cardID;
    private byte cardSoftVers;
    private boolean cardAuthenticated = false;
    private byte cardType;
    private int petrolQuota;
    private byte[] nonceC;
    private byte[] nonceT;

    public TMan(JFrame parent) {
        skey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, true);

        keyExchangeKP = new KeyPair(KeyPair.ALG_EC_FP, (short) 128); // Use 128 for easy match with AES 128
        TMan = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TChar = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TCons = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        Server = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        Card = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        ReCard = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);

        AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        ECExch = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        //simulatorInterface = new JavaxSmartCardInterface(); // SIM
        buildGUI(parent);
        setEnabled(false);
        (new SimulatedCardThread()).start();
    }


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
        key("Personalise");
        key("Authenticate");
        key("Quit");
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

    private void resetTerminal(){
        cardID = new byte[] {0,0,0,0};
        cardSoftVers = 0;
        cardAuthenticated = false;
        cardType = 0;
        petrolQuota = 0;
        
        nonceC = new byte[] {0,0,0,0, 0,0,0,0};
        nonceT = new byte[] {0,0,0,0, 0,0,0,0};
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

    class SimulatedCardThread extends Thread {
        public void run() {
          // Create simulator and install applet
          CardSimulator simulator = new CardSimulator();
          AID cardAppletAID = new AID(CALC_APPLET_AID,(byte)0,(byte)7);
          simulator.installApplet(cardAppletAID, CardApplet.class);

          // Obtain a CardTerminal
          CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
          
          // Insert Card into "My terminal 1"
          simulator.assignToTerminal(terminal);

          try {
            Card card = terminal.connect("T=1");

    	    applet = card.getBasicChannel();
    	    ResponseAPDU resp = applet.transmit(SELECT_APDU);
    	    if (resp.getSW() != 0x9000) {
    	      throw new Exception("Select failed");
    	    }
    	    //setText(sendKey((byte) '='));
            System.out.println("Reading card now:");
            setText(readCard());
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
                        setText(authenticate());
                        break;
                    case 'P':
                        setText(personalise());
                        break;
                    case 'Q':
                        System.exit(0);
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
    
    public int readCard() {                                                 //default method, read information on card
        resetTerminal();

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

        cardType = data[0];
        cardSoftVers = data[1];

        System.arraycopy(data, 2, cardID, 0, 4);
        petrolQuota = (int) Util.getShort(data, (short) 6);

        System.out.printf("Read response from Card: Type: %x; Soft Vers: %x; ID: %x%x%x%x; Petrolquota: %x \n", 
                cardType, cardSoftVers, cardID[0], cardID[1], cardID[2], cardID[3], petrolQuota);
        return (int) petrolQuota;
    }

    public String authenticate() {
        // First initialise the session key
        resetTerminal();
        byte[] buffer = new byte[93];
        keyExchangeKP.genKeyPair();

        System.arraycopy(T_ID, 0, buffer, 0, 4);
        ((ECPublicKey) keyExchangeKP.getPublic()).getW(buffer, (short) 4);

        // produce signature and add that to the buffer
        signature.init(TMan.getPrivate(), Signature.MODE_SIGN);
        signature.update(new byte[] {T_TYPE, T_SOFT_VERSION}, (short) 0, (short) 2);
        signature.sign(buffer, (short) 0, (short) 37, buffer, (short) 37);

        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU command = new CommandAPDU(PRFE_CLA, AUTH_INS, T_TYPE, T_SOFT_VERSION, buffer, 0, 93, 161);

        ResponseAPDU response;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(command);
        } catch (CardException e) {
            // TODO: do something with the exception

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
        
        byte[] data = response.getData(); 
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
            return "Auth failed, CCert invalid";
        }

        // Finally store verified data of the card
        System.arraycopy(data, 33, cardID, 0, 4);
        cardAuthenticated = true;
        
        // ================== Authentication Phase 2
        // Move forward with authenticating Terminal to card


        
        return "Authentication Successful";

    }

    public String personalise () {
        byte[] buffer0 = new byte[228];
        byte[] buffer1 = new byte[172];

        /**
         * TODO: put this in report:
         * we do not do appropriate key management in this example. 
         * For personalisation the keys are simply generated, and the card is only persistently usable for a single run of the simulator.
         * In reality, the keypairs are the same for all devices of the same category.
         */
        // first generate all the keys:
        TMan.genKeyPair(); 
        TChar.genKeyPair(); 
        TCons.genKeyPair(); 
        Server.genKeyPair(); 
        Card.genKeyPair(); 
        ReCard.genKeyPair(); 

        // Then add them to buffers:
        ((ECPublicKey) TMan.getPublic()).getW(buffer0, (short) 0);
        ((ECPublicKey) TChar.getPublic()).getW(buffer0, (short) 51);
        ((ECPublicKey) TCons.getPublic()).getW(buffer0, (short) 102);
        ((ECPublicKey) Card.getPublic()).getW(buffer0, (short) 153);
        ((ECPrivateKey) Card.getPrivate()).getS(buffer0, (short) 204);

        ((ECPublicKey) ReCard.getPublic()).getW(buffer1, (short) 0);
        ((ECPublicKey) Server.getPublic()).getW(buffer1, (short) 51);

        // generate cardID // TODO: put in the report that we now use a fixed cardID for easier testing, but that this could just as well be dynamic
        byte[] cardID = new byte[] {(byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef};

        // generate CCert
        signature.init(Server.getPrivate(), Signature.MODE_SIGN);
        signature.update(cardID, (short) 0, (short) 4);
        signature.update(new byte[] {0x00}, (short) 0, (short) 1);
        signature.sign(CCertExp, (short) 0, (short) 4, buffer1, (short) 102); // outputs 54, 55 or 56 bytes of signature data

        System.arraycopy(CCertExp, 0, buffer1, 158, 4);
        System.arraycopy(cardID, 0, buffer1, 162, 4);
        
        // Generate random 6 digit pin using SecureRandom
        byte[] pin = new byte[6];
        SecureRandom random = new SecureRandom();
        int pinInt = random.nextInt(1000000);
        
        pin[0] = (byte) (pinInt - (pinInt % 100000));
        pin[1] = (byte) ((pinInt % 100000) - (pinInt % 10000));
        pin[2] = (byte) ((pinInt % 10000) - (pinInt % 1000));
        pin[3] = (byte) ((pinInt % 1000) - (pinInt % 100));
        pin[4] = (byte) ((pinInt % 100) - (pinInt % 10));
        pin[5] = (byte) (pinInt % 10);
        System.arraycopy(pin, 0, buffer1, 166, 6);
        

        ResponseAPDU response;
        CommandAPDU readCommand = new CommandAPDU(PRFE_CLA, PERS_INS, (byte) 1, T_SOFT_VERSION, buffer0, 0, 228, 228);
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return "ERROR: cardException";
        }
        // Check that the response is the same as what was sent:
        byte[] data = response.getBytes(); 
        if (data[0] == 0x62 && data[1] == 0) {
            return "Warning: Card not manageable!";
        }
        data = response.getData();
        byte[] dataTrunc = Arrays.copyOfRange(data, 0, 228);
        if (!Arrays.equals(buffer0, dataTrunc)) {
            for (int i = 0; i < 172; i++) {
                if (buffer0[i] != dataTrunc[i]) {
                    System.out.printf("%d %x %x \n", i, buffer0[i], dataTrunc[i]);
                }
            }
            return "ERROR: Card readback 0 incorrect!";
        }

        readCommand = new CommandAPDU(PRFE_CLA, PERS_INS, (byte) 0b00000011, T_SOFT_VERSION, buffer1, 0, 172, 172);
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return "ERROR: cardException";
        }
        // Check that the response is the same as what was sent:
        data = response.getData(); 
        byte[] dataTrunc1 = Arrays.copyOfRange(data, 0, 172);
        if (!Arrays.equals(buffer1, dataTrunc1)) {
            /*for (int i = 0; i < 172; i++) {
                if (buffer1[i] != dataTrunc1[i]) {
                    System.out.printf("%d %x %x \n", i, buffer1[i], dataTrunc1[i]);
                }
            }*/
            return "ERROR: Card readback 1 incorrect!";
        }

        System.out.println("Disabling personalisation...");
        // Disable personalise
        readCommand = new CommandAPDU(PRFE_CLA, PERS_INS, (byte) 0b00000100, T_SOFT_VERSION);
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(readCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return "ERROR: cardException";
        }
        return "Personalisation success!";
    }
    
    
    public boolean disableManageable(){
      //set managable on card to false
      //return true on succes
      return true;
    }

    public boolean getManageable(){
      //get the managable status from card and return this
      return true;
    }

    public String getInfo(){
      //get version number
      return "0.0.1";
    }

    public boolean updateSoftware(){
      //do we even want to program this or just as a placeholder?
      return true;
    }

    public String getOwner(){
      //get owner name
      return "nobody";
    }

    public boolean setOwner(String name){
      if(!getManageable()){
        return false;
      } else {
        // set owner
        // on succes return true
        return true;
      }
    }

    public boolean setKey(int keyNumber, String key) {
      if(!getManageable()){
        return false;
      } else {
        // set one key
        // on succes return true
        return true;
      }
    }

    public boolean setKeys(String[] keys) {
      if(!getManageable()){
        return false;
      } else {
        // set all keys at once
        // on succes return true
        return true;
      }
    }

    public boolean setPetrolCredits(int PC) {
      // change pc on card to PC
      // return true on succes
      return true;
    }

    public int getPetrolCredits() {
      // get the pc that are on the card
      // return an int
      return 0;
    }

    public boolean rekeyCard(){
      // do some magic to rekey the card
      return true;
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
        TMan panel = new TMan(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
