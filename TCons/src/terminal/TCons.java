package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;

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

import javacard.security.*;
import javax.crypto.*;
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
    private byte[] Sver;                   // Software version of the Terminal

    private byte TERMINAL_SOFTWARE_VERSION;

    private static final byte TERMINAL_TYPE = (byte) 0x3;


    //keys
    private ECPublicKey pukc;             // public key Card
    private ECPrivateKey prkTCons;        // private key TCons
    private ECPublicKey purkTCons;        // public rekey TCons
    private ECPublicKey puks;             // Server certificate verification key
    private byte[] TCert;                 // Terminal certificate signed with prks

    private AESKey skey;                  // Session key

    //Instruction bytes
    private static final byte PRFE_CLA = (byte) 0xB0;
    private static final byte READ_INS = (byte) 0x00;
    private static final byte AUTH_INS = (byte) 0x10;
    private static final byte CONS_INS = (byte) 0x30;
    private static final byte REV_INS  = (byte) 0x40;

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

        TCert = null;                                                                      // Terminal certificate containing
                                                                                           // ID, type of device and expiry date
        tID = new byte[4];


        //simulatorInterface = new JavaxSmartCardInterface(); // SIM
        buildGUI(parent);
        setEnabled(false);
        (new SimulatedCardThread()).start();
    }

    //functions

    public void readCard(){                                                 //default method, read information on card
        //construct a commandAPDU with the INS byte for read and the terminal info
        CommandAPDU readCommand = new CommandAPDU((byte) PRFE_CLA, (byte) READ_INS, (byte)TERMINAL_TYPE, (byte)TERMINAL_SOFTWARE_VERSION);
        //card sends back apdu with the data after transmitting the commandAPDU to the card
        ResponseAPDU response = applet.transmit(readCommand);
        //process the response apdu and display the information on the terminal?
        byte[] responseBytes = response.getBytes();
        byte[] data = response.getData(); //data for read command is the card id and the petrol credits?
        //parseData(byte[] data)?
        //setText(response);
        //alternatively maybe use the setText(response) to extract the data from the apdu and display on terminal?
    };

    public byte[] getCardData(ResponseAPDU response){
        byte[] data = response.getData();
        return data;
    }

    public byte[] getCardID(byte[] data){

        return data;
    }

    public int getPetrolCredit(byte[] data){
        //get petrol credit from the card
        //
        //
        return 0;
    };

    public void authenticateCardAndBuyer(CardApplet card){                                                         //authenticate card and buyer before we perform any transactions
        //authenticate card
        //buyer provides pin to terminal
        //terminal presents pin to card
        //if card returns true for isValidated(), buyer is authenticated
        //else it returns number of tries left for the pin, if this is 0, the card is blocked: exit
    };

    public void consumeQuota(int amount, int balance){                                                        //use an amount of petrol quota on the card
        //amount = entered by the buyer
        //card has quota balance
        if (balance - amount < 0){

        }
        //if quota on card - amount < 0 : exit
        //else

    };


    void setMaxGas(){
        //read balance from the card
        int balance = getPetrolCredit();
        //
        //
    };                                                                             //set the max amount of gas available to the buyer based on the quota on card (a short?)

    short getGasUsed();                                                                                          //return the amount of gas dispensed

    public byte[] sign(byte[] data, byte[] key){
        Signature sign = Signature.getInstance("");                               //determine signing algorithm
        sign.initSign(key);
        sign.update(data);
        byte[] signature = sign.sign();
        return signature;
    };

    public byte[] hash(byte[] data){
        //create message digest using a certain hash algorithm
        MessageDigest md = MessageDigest.getInstance("") //TODO: decide hash algorithm?
        //use hash to hash the data
        md.update(data);
        //generate the hash of the data
        byte[] hash = md.digest();
        return hash;

    };

    public byte[] mac(byte[] data){                                                                              //mac code for sending data between card and terminal, using java.crypto.Mac object?
        //create mac object
        Mac mac = Mac.getInstance(""); //TODO: algorithm for mac?
        //initialise the Mac object with the skey
        mac.init(skey);
        //compute mac
        byte[] macResult = mac.doFinal(data);
        return macResult;
    };

    public boolean verify(byte[] data, byte[] key);

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
        key(null);
        key(null);
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
                setText(sendKey((byte) c));
            }
        } catch (Exception e) {
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
