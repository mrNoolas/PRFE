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
import java.util.Set;
import java.util.HashSet;
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
    private byte[] rekeySign = new byte[58];
    private short keySetVersion = 0;

    private Signature signature;

    /**
     * TODO: really this should keep more records: e.g. when the card was revoked, why, by which terminal, etc.
     */
    private Set<byte[]> revokedCards;

    public TermSim (JFrame tManParent, JFrame tConsParent, JFrame tCharParent) {
        revokedCards = new HashSet();

        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

        TManKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TCharKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        TConsKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        ServerKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        CardKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);
        ReCardKP = new KeyPair(KeyPair.ALG_EC_F2M, (short) 193);

        // generate all the keys:
        TManKP.genKeyPair();
        TCharKP.genKeyPair();
        TConsKP.genKeyPair();
        ServerKP.genKeyPair();
        CardKP.genKeyPair();
        ReCardKP.genKeyPair();

        signature.init(ReCardKP.getPrivate(), Signature.MODE_SIGN);
        rekeySign[0] = (byte) (keySetVersion & 0xff);
        rekeySign[1] = (byte) ((keySetVersion >> 8) & 0xff);
        signature.update(rekeySign, (short) 0, (short) 2);

        byte[] buffer = new byte[228];
        ((ECPublicKey) TManKP.getPublic()).getW(buffer, (short) 0);
        ((ECPublicKey) TCharKP.getPublic()).getW(buffer, (short) 51);
        ((ECPublicKey) TConsKP.getPublic()).getW(buffer, (short) 102);
        ((ECPublicKey) CardKP.getPublic()).getW(buffer, (short) 153);
        ((ECPrivateKey) CardKP.getPrivate()).getS(buffer, (short) 204);
        signature.sign(buffer, (short) 0, (short) 228, rekeySign, (short) 2);

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

        public byte[] revokeCard(byte[] cardID) {
            if (cardID.length == 4) { // if not 4 then it is an invalid ID
                revokedCards.add(cardID);
            } else {
                return null;
            }

            byte[] signOut = new byte[56];

            // then make signature
            signature.init(ServerKP.getPrivate(), Signature.MODE_SIGN);
            signature.update(cardID, (short) 0, (short) 4);
            // add "server revoke"; really this should be the ID of the server and the ID of the terminal that initiated a revoke
            signature.sign(new byte[] {(byte) 0x73, (byte) 0x65, (byte) 0x72, (byte) 0x76, (byte) 0x65, (byte) 0x72,
                    (byte) 0x20, (byte) 0x72, (byte) 0x65, (byte) 0x76, (byte) 0x6f, (byte) 0x6b, (byte) 0x65},
                    (short) 0, (short) 13, signOut, (short) 0);
            return signOut;
        }

        public boolean isRevokedCard(byte[] cardID) {
            return revokedCards.contains(cardID);
        }

        public byte[] getRekeySignature() {
            return rekeySign;
        }

        public short requestRekey(boolean rekeyCard, boolean rekeyTMan, boolean rekeyTChar, boolean rekeyTCons) {
            if (rekeyCard || rekeyTChar || rekeyTCons || rekeyTMan) {
                keySetVersion++;

                // genKeyPair automatically updates all terminals due to object references
                if (rekeyTMan) TManKP.genKeyPair();
                if (rekeyTChar) TCharKP.genKeyPair();
                if (rekeyTCons) TConsKP.genKeyPair();
                // ServerKP.genKeyPair();
                if (rekeyCard) CardKP.genKeyPair();
                // ReCardKP.genKeyPair();

                signature.init(ReCardKP.getPrivate(), Signature.MODE_SIGN);
                rekeySign[0] = (byte) (keySetVersion & 0xff);
                rekeySign[1] = (byte) ((keySetVersion >> 8) & 0xff);
                signature.update(rekeySign, (short) 0, (short) 2);

                byte[] buffer = new byte[228];
                ((ECPublicKey) TManKP.getPublic()).getW(buffer, (short) 0);
                ((ECPublicKey) TCharKP.getPublic()).getW(buffer, (short) 51);
                ((ECPublicKey) TConsKP.getPublic()).getW(buffer, (short) 102);
                ((ECPublicKey) CardKP.getPublic()).getW(buffer, (short) 153);
                ((ECPrivateKey) CardKP.getPrivate()).getS(buffer, (short) 204);
                signature.sign(buffer, (short) 0, (short) 228, rekeySign, (short) 2);
            }

            return keySetVersion;
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
