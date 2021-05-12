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

    // keys
    private ECPrivateKey prTMan;     // private key TMan
    private ECPublicKey pukTMan;     // public key TChar
    private ECPublicKey pukTChar;    // public key TChar
    private ECPublicKey pukTCons;    // public key TCons
    private ECPrivateKey prkc;       // private key Card
    private ECPublicKey pukc;        // public key Card
    private ECPrivateKey prrkc;      // private rekey Card
    private ECPrivateKey prrkt;      // private rekey Terminal
    private ECPublicKey puks;        // Server certificate verification key
    private byte[] CCert;            // Server certificate verification key

    private AESKey skey;

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

    public TMan(JFrame parent) {
        skey = KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, LENGTH_AES_128, true);
        status = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        status[0] = 0x00; // unitialised

        prkTMan  = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true); // private key TMan
        pukTMan  = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TMan
        pukTChar = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TChar
        pukTCons = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true); // public key TCons
        prkc     = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);       // private key Card
        pukc     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true);       // public key Card
        prrkt    = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);      // private rekey Terminal
        prrkc    = KeyBuilder.buildKey(TYPE_EC_F2M_PRIVATE, LENGTH_F2M_193, true);      // private rekey Card
        puks     = KeyBuilder.buildKey(TYPE_EC_F2M_PUBLIC, LENGTH_F2M_193, true);       // Server certificate verification key
        CCert;      // Server certificate verification key



        /*xy = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
        lastOp = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        lastKeyWasDigit = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
        m = 0;*/
        register();

        // original code: ===========================================================================
        /simulatorInterface = new JavaxSmartCardInterface(); // SIM
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

    public boolean disableManageable(){
      //set managable on card to false
      //return true on succes
    }

    public boolean getManageable(){
      //get the managable status from card and return this
    }

    public String getInfo(){
      //get version number
    }

    public boolean updateSoftware(){
      //do we even want to program this or just as a placeholder?
    }

    public String getOwner(){
      //get owner name
    }

    public boolean setOwner(String name){
      if(!getManagable()){
        return false;
      } else {
        // set owner
        // on succes return true
        return true;
      }
    }

    public boolean setKey(int keyNumber, String key) {
      if(!getManagable()){
        return false;
      } else {
        // set one key
        // on succes return true
        return true;
      }
    }

    public boolean setKeys(String[] keys) {
      if(!getManagable()){
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
    }

    public int getPetrolCredits() {
      // get the pc that are on the card
      // return an int
    }

    public boolean rekeyCard(){
      // do some magic to rekey the card
    }

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
        TMan panel = new TMan(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
