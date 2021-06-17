package terminal;

import terminal.TMan;
import terminal.TChar;

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

public class TermSim {
    static final byte[] PRFE_APPLET_AID = { (byte) 0x3B, (byte) 0x29, (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String PRFE_APPLET_AID_string = "3B2963616C6301";
    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, PRFE_APPLET_AID);

    CardChannel applet;

    static final String TITLE = "Terminal";

    private TMan tMan;
    private TCons tCons;
    private TChar tChar;

    private KeyPair TManKP;
    private KeyPair TCharKP;
    private KeyPair TConsKP;
    private KeyPair ServerKP; // Note: for this POC terminals also act as server.
    private KeyPair CardKP;
    private KeyPair ReCardKP;

    public TermSim (JFrame tManParent, JFrame tConsParent, JFrame tCharParent) {
        TManKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TCharKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TConsKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        ServerKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        CardKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        ReCardKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);

        /**
         * TODO: put this in report:
         *
         */
        // generate all the keys:
        TManKP.genKeyPair();
        TCharKP.genKeyPair();
        TConsKP.genKeyPair();
        ServerKP.genKeyPair();
        CardKP.genKeyPair();
        ReCardKP.genKeyPair();

        // Setup Terminals TODO: reduce the keys that are given to each terminal
        tMan = new TMan(tManParent, TManKP, TCharKP, TConsKP, ServerKP, CardKP, ReCardKP);
        tCons = new TCons(tConsParent, TManKP, TCharKP, TConsKP, ServerKP, CardKP, ReCardKP);
        tChar = new TChar(tConsParent, TManKP, TCharKP, TConsKP, ServerKP, CardKP, ReCardKP);

        tManParent.addWindowListener(new CloseEventListener());
        tConsParent.addWindowListener(new CloseEventListener());
        tCharParent.addWindowListener(new CloseEventListener());

        (new SimulatedCardThread()).start();

        tMan.setEnabled(true);
        tCons.setEnabled(false);
        tChar.setEnabled(false);
    }

    private TMan getTMan() {
        return tMan;
    }
    private TCons getTCons() {
        return tCons;
    }

    private TChar getTChar() {
        return tChar;
    }

    class SimulatedCardThread extends Thread implements TerminalSwitch {
        CardTerminal TMAN, TCONS, TCHAR;
        CardSimulator simulator;

        public void run() {
            // Create simulator and install applet
            simulator = new CardSimulator();
            AID cardAppletAID = new AID(PRFE_APPLET_AID,(byte)0,(byte)7);
            simulator.installApplet(cardAppletAID, CardApplet.class);

            // Obtain a CardTerminal
            TMAN = CardTerminalSimulator.terminal(simulator);
            TCONS = CardTerminalSimulator.terminal(simulator);
            TCHAR = CardTerminalSimulator.terminal(simulator);

            tMan.switchCallback = this;
            tCons.switchCallback = this;
            tChar.switchCallback = this;

            switchTerminal((byte) 0x01); // switch to TMAN
        }

        public void switchTerminal(byte t) {
            tMan.setEnabled(false);
            tCons.setEnabled(false);
            tChar.setEnabled(false);
            System.out.println(t);

            if ((t & 0xff) == (byte) 0x01) {
                tMan.setEnabled(true);

                // Insert Card into TMAN
                simulator.assignToTerminal(TMAN);

                try {
                    Card card = TMAN.connect("T=1");
                    tMan.applet = card.getBasicChannel();

                    ResponseAPDU resp = tMan.applet.transmit(SELECT_APDU);
                    if (resp.getSW() != 0x9000) {
                        throw new Exception("Select failed");
                    }
                } catch (Exception e) {
                    System.err.println("Card status problem!");
                }

            } else if ((t & 0xff) == (byte) 0x02) {
                tChar.setEnabled(true);

                // Insert Card into TMAN
                simulator.assignToTerminal(TCHAR);

                try {
                    Card card = TCHAR.connect("T=1");
                    tChar.applet = card.getBasicChannel();

                    ResponseAPDU resp = tChar.applet.transmit(SELECT_APDU);
                    if (resp.getSW() != 0x9000) {
                        throw new Exception("Select failed");
                    }
                } catch (Exception e) {
                    System.err.println("Card status problem!");
                }
            } else if ((t & 0xff) == (byte) 0x03) {
                tCons.setEnabled(true);

                // Insert Card into TCONS
                simulator.assignToTerminal(TCONS);

                try {
                    Card card = TCONS.connect("T=1");
                    tCons.applet = card.getBasicChannel();

                    ResponseAPDU resp = tCons.applet.transmit(SELECT_APDU);
                    if (resp.getSW() != 0x9000) {
                        throw new Exception("Select failed");
                    }
                } catch (Exception e) {
                    System.err.println("Card status problem!");
                }
            }
        }
    }

    class CloseEventListener extends WindowAdapter {
        public void windowClosing(WindowEvent we) {
            System.exit(0);
        }
    }

    public static void main(String[] arg) {
        JFrame tManFrame = new JFrame("Management Terminal");
        Container tManC = tManFrame.getContentPane();
        JFrame tConsFrame = new JFrame("Consumption Terminal");
        Container tConsC = tConsFrame.getContentPane();
        JFrame tCharFrame = new JFrame("Charging Terminal");
        Container tCharC = tCharFrame.getContentPane();

        TermSim sim = new TermSim(tManFrame, tConsFrame, tCharFrame);

        TMan tManPane = sim.getTMan();
        tManC.add(tManPane);
        TCons tConsPane = sim.getTCons();
        tConsC.add(tConsPane);
        TChar tCharPane = sim.getTChar();
        tCharC.add(tCharPane);

        tManFrame.setResizable(false);
        tManFrame.pack();
        tManFrame.setVisible(true);

        tConsFrame.setResizable(false);
        tConsFrame.pack();
        tConsFrame.setVisible(true);

        tCharFrame.setResizable(false);
        tCharFrame.pack();
        tCharFrame.setVisible(true);
    }
}