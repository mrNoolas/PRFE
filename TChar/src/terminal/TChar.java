package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.*;
import javacard.security.*;

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

import javax.crypto.*;

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
public class TChar extends JPanel implements ActionListener {

	private byte[] tID;
	private byte[] Sver;
	private byte TERMINAL_SOFTWARE_VERSION;
	private static final byte TERMINAL_TYPE = (byte) 0x2;

	// keys
	private ECPublicKey pukc; // public key Card
	private ECPrivateKey prkTChar; // private key TChar
	private ECPublicKey purkTChar; // public rekey key TChar
	private ECPublicKey puks; // certificate verification key
	private byte[] TCert; // Terminal certificate

	//Instruction bytes
    private static final byte PRFE_CLA = (byte) 0xB0;
    private static final byte READ_INS = (byte) 0x00;
    private static final byte AUTH_INS = (byte) 0x10;
    private static final byte CHAR_INS = (byte) 0x20;
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

    public TChar(JFrame parent) {
        //simulatorInterface = new JavaxSmartCardInterface(); // SIM
        buildGUI(parent);
        setEnabled(false);
        (new SimulatedCardThread()).start();


		skey      = (AESKey)       KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128,true);
		pukc      = (ECPublicKey)  KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC,  KeyBuilder.LENGTH_EC_F2M_193, true);
		prkTChar  = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PRIVATE, KeyBuilder.LENGTH_EC_F2M_193, true);
		purkTChar = (ECPublicKey)  KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC,  KeyBuilder.LENGTH_EC_F2M_193, true);
		puks      = (ECPublicKey)  KeyBuilder.buildKey(KeyBuilder.TYPE_EC_F2M_PUBLIC,  KeyBuilder.LENGTH_EC_F2M_193, true);
		TCert     = null;




    }

	public void readCard(CardApplet card) {
		// This function reads the information from the presented card given by parameter card
		// Send APDU to card
		// Receive APDU from card containing a response
		// Process response
		// Show response on terminal

		CommandAPDU readCommand = new CommandAPDU((int)PRFE_CLA, (int) READ_INS, (int)TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION);

		ResponseAPDU response = card.transmit(readCommand);

		byte[] responseBytes = response.getBytes();
	}

	public void authenticateCardAndBuyer(CardApplet card) {
		// This function ensures that the card and the buyer are properly authenticated before starting a transaction
		// Authenticate the card
		// User enters PIN
		// Terminal accepts PIN: user is authenticated
		// Terminal declines PIN: user is not authenticated
	}

	public byte[] hash(byte[] data) {
		// Hash the message using hash function
		MessageDigest md = MessageDigest.getInstance("");
		md.update(data);

		byte[] hash = md.digest();
		return hash;
	}

	public boolean verify(byte[] data, byte[] key) {
		// Verify if a given signature is correct
		// If correct: output true
		// If incorrect: output false
	}

	public byte[] sign(byte[] data, byte[] key) {
		// Sign a given message to ensure integrity

	}

	public byte[] mac(byte[] data) {
		// Returns the MAC of the data
		Mac mac = Mac.getInstance("");
		mac.init(skey);

		byte[] macResult = mac.doFinal(data);
		return macResult;
	}

	public void updateQuota(CardApplet card, int amount) {
		// Updates the quota on the card
		// Requires authenticateCardAndBuyer()
		// new_amount = old_amount + quota
		CommandAPDU chargeCommand = new CommandAPDU((int)PRFE_CLA, (int) CHAR_INS);

		ResponseAPDU response = card.transmit(chargeCommand);

		byte[] responseBytes = response.getBytes();

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

    /* Original code to connect the terminal with a physical smartcard
     * in a reader using javax.smartcardio
     */
    /*
    class CardThread extends Thread {
        public void run() {
            try {
            	TerminalFactory tf = TerminalFactory.getDefault();
    	    	CardTerminals ct = tf.terminals();
    	    	List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
    	    	if (cs.isEmpty()) {
    	    		System.err.println("No terminals with a card found.");
    	    		return;
    	    	}

    	    	while (true) {
    	    		try {
    	    			for(CardTerminal c : cs) {
    	    				if (c.isCardPresent()) {
    	    					try {
    	    						Card card = c.connect("*");
    	    						try {
    	    							applet = card.getBasicChannel();
    	    							ResponseAPDU resp = applet.transmit(SELECT_APDU);
    	    							if (resp.getSW() != 0x9000) {
    	    								throw new Exception("Select failed");
    	    							}
    	    	    	    			setText(sendKey((byte) '='));
    	    	                        setEnabled(true);

    	    	                        // Wait for the card to be removed
    	    	                        while (c.isCardPresent());
    	    	                        setEnabled(false);
    	    	                        setText(MSG_DISABLED);
    	    	                        break;
    	    						} catch (Exception e) {
    	    							System.err.println("Card does not contain CardApplet?!");
    	    							setText(MSG_INVALID);
    	    							sleep(2000);
    	    							setText(MSG_DISABLED);
    	    							continue;
    	    						}
    	    					} catch (CardException e) {
    	    						System.err.println("Couldn't connect to card!");
    	    						setText(MSG_INVALID);
    	    						sleep(2000);
    	    						setText(MSG_DISABLED);
    	    						continue;
    	    					}
    	    				} else {
    	    					System.err.println("No card present!");
    	    					setText(MSG_INVALID);
    	    					sleep(2000);
    	    					setText(MSG_DISABLED);
    	    					continue;
    	    				}
    	    			}
    	    		} catch (CardException e) {
    	    			System.err.println("Card status problem!");
    	    		}
    	    	}
            } catch (Exception e) {
                setEnabled(false);
                setText(MSG_ERROR);
                System.out.println("ERROR: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
    */

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
        TChar panel = new TChar(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
