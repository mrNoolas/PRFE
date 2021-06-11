package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
//import javax.crypto.*;

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
public class TChar extends JPanel implements ActionListener {

	private byte[] tID;
	private byte[] Sver;
	private byte[] nonceT;
	private byte TERMINAL_SOFTWARE_VERSION;
	private static final byte TERMINAL_TYPE = (byte) 0x2;

	// keys
	private ECPublicKey pukc; // public key Card
	private ECPrivateKey prkTChar; // private key TChar
	private ECPublicKey purkTChar; // public rekey key TChar
	private ECPublicKey puks; // certificate verification key

	private AESKey skey;
	private Signature signature;
	private javacardx.crypto.Cipher AESCipher;

	private byte[] TCert; // Terminal certificate
	

	//Length constants
	private static final short ID_LENGTH = 4;
	private static final short NONCE_LENGTH = 8;
	private static final short TID_LENGTH     = 4;
    private static final short NONCET_LENGTH  = 8;
    private static final short AES_KEY_LENGTH = 16;

	private static final short SIGN_LENGTH = 56;
	//Instruction bytes

    private static final byte PRFE_CLA = (byte) 0xB0;
    private static final byte READ_INS = (byte) 0x00;
    private static final byte AUTH_INS = (byte) 0x10;
    private static final byte CHAR_INS = (byte) 0x20;
    private static final byte REV_INS  = (byte) 0x40;

	private byte[] cardID;

    // Data about this terminal:
    private static final byte T_TYPE = (byte) 0x02;
    private static final byte T_SOFT_VERSION = (byte) 0x00;
    private static final byte[] T_ID = {(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01};

	private short monthlyQuota;


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


		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		AESCipher = javacardx.crypto.Cipher.getInstance(javacardx.crypto.Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

		tID = new byte[TID_LENGTH];
		nonceT = new byte[NONCET_LENGTH];
		byte[] cardID = new byte[4];
		monthlyQuota = 1;



    }

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

				
				System.arraycopy(data, 2, cardID, 0, 4);

				short petrolQuota = Util.getShort(data, (short) 6);

				System.out.printf("Read response from Card: Type: %x; Soft Vers: %x; ID: %x%x%x%x; Petrolquota: %x \n",
								cardType, cardSoftVers, cardID[0], cardID[1], cardID[2], cardID[3], petrolQuota);
				return (int) petrolQuota;
		}

	public void authenticateCardAndBuyer(CardApplet card) {
		// This function ensures that the card and the buyer are properly authenticated before starting a transaction
		// Authenticate the card
		// User enters PIN
		// Terminal accepts PIN: user is authenticated
		// Terminal declines PIN: user is not authenticated
	}


	public void charge(CardApplet card) throws CardException, Exception{
		byte[] sigBuffer = new byte[2*SIGN_LENGTH];

		signature.init(skey, Signature.MODE_SIGN);
		signature.sign(nonceT, (short) 0, (short) 8, sigBuffer, (short) 0);
		CommandAPDU chargeCommand = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int)TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, sigBuffer);
		ResponseAPDU response = null;
		try {
			response = applet.transmit(chargeCommand);
		} catch (CardException e) {
			System.out.println(e);
		}

		byte[] data = response.getData();
		
		System.arraycopy(data, 0, cardID, 0, 4);

		short petrolQuota = Util.getShort(data, (short) 4);

		short tNum = Util.getShort(data, (short) 6);

		System.arraycopy(data, 0, sigBuffer, 0, 8);
		incNonce(nonceT);
		System.arraycopy(nonceT, 0, sigBuffer, 8, NONCET_LENGTH);

		signature.init(skey, Signature.MODE_VERIFY);
		if (!signature.verify(sigBuffer, (short) 0, (short) 16, data, (short) 8, SIGN_LENGTH)) {


			// do something


		}

		short extraQuota = getMonthlyQuota(cardID);
		data[4] = (byte) (extraQuota & 0xff);
		data[5] = (byte) ((extraQuota >> 8) & 0xff);

		data[6] = (byte) (tNum & 0xff);
		data[7] = (byte) ((tNum >> 8) & 0xff);
		incNonce(nonceT);

		System.arraycopy(nonceT, 0, data, 8, NONCET_LENGTH);


		signature.init(skey, Signature.MODE_SIGN);
		signature.sign(data, (short) 0, (short) 16, data, (short) 8);
		chargeCommand = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int) TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, data);
		try {
			response = applet.transmit(chargeCommand);
		} catch (CardException e) {
			System.out.println(e);
		}


		data = response.getData();
		System.arraycopy(cardID, 0, sigBuffer, 0, 4);
		System.arraycopy(TCert, 0, sigBuffer, 4, SIGN_LENGTH);
		petrolQuota += extraQuota;
		sigBuffer[60] = (byte) (petrolQuota & 0xff);
		sigBuffer[61] = (byte) ((petrolQuota >> 8) & 0xff);
		sigBuffer[62] = (byte) (tNum & 0xff);
		sigBuffer[63] = (byte) ((tNum >> 8) & 0xff);

		signature.init(skey, Signature.MODE_VERIFY);

		if (!signature.verify(sigBuffer, (short) 0, (short) 64, data, (short) 0, SIGN_LENGTH)) {

			// do something
		}

		incNonce(nonceT);
		if (!signature.verify(nonceT, (short) 0, (short) 8, data, SIGN_LENGTH, SIGN_LENGTH)) {
			// do something
		}


	}

	private short getMonthlyQuota(byte[] cardID) {
		return (short) 1;
	}


	public void revoke(CardApplet card) {
		byte[] sigBuffer = new byte[SIGN_LENGTH+NONCET_LENGTH];
		sigBuffer[0] = REV_INS;
		System.arraycopy(cardID, (short) 0, sigBuffer, (short) 1, (short) 4);
		System.arraycopy(nonceT, (short) 0, sigBuffer, (short) 5, NONCET_LENGTH);
		
		signature.init(skey, Signature.MODE_SIGN);
		signature.sign(sigBuffer, (short) 0, (short) 13, sigBuffer, (short) 0);
		System.arraycopy(nonceT, (short) 0, sigBuffer, SIGN_LENGTH, NONCET_LENGTH);
		CommandAPDU revokeCommand = new CommandAPDU((int) PRFE_CLA, (int) REV_INS, (int) TERMINAL_TYPE, (int) TERMINAL_SOFTWARE_VERSION, sigBuffer);
		ResponseAPDU response;

		try {
			response = applet.transmit(revokeCommand);
		} catch (CardException e) {
			System.out.println(e);
		}
		
	}

	public byte[] hash(byte[] data) {
		// Hash the message using hash function
		byte[] hash = null;
		MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		md.doFinal(data, (short) 0, (short) data.length, hash, (short) 0);
		md.reset();
		return hash;
	}

	public void updateQuota(CardApplet card) {
		// Updates the quota on the card
		// Requires authenticateCardAndBuyer()
		// new_amount = old_amount + quota


		CommandAPDU chargeCommand = new CommandAPDU((int)PRFE_CLA, (int) CHAR_INS, (int) TERMINAL_TYPE, (int) TERMINAL_SOFTWARE_VERSION);
		ResponseAPDU response = null;
		try {
			response = applet.transmit(chargeCommand);
		} catch (CardException e) {
			System.out.println(e);
		}

		byte[] responseBytes = response.getBytes();
		byte[] data = response.getData();


		short petrolCredit = data[(short) 0];
		petrolCredit = (short) (petrolCredit + monthlyQuota);
		chargeCommand = new CommandAPDU((int)PRFE_CLA, (int) CHAR_INS, (short) monthlyQuota, (int) 0);
		try {
			response = applet.transmit(chargeCommand);
		} catch (CardException e) {
			System.out.println(e);
		}




	}

	public short getPetrolCredit(byte[] data){
        //get petrol credit from the card
        //
        //
        return 0;
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
        TChar panel = new TChar(frame);
        c.add(panel);
        frame.setResizable(false);
        frame.pack();
        frame.setVisible(true);
    }
}
