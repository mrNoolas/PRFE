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
import terminal.PRFETerminal;

public class TChar extends PRFETerminal {
    private static final byte PERS_INS = (byte) 0x50;
    private static final byte CHAR_INS = (byte) 0x20;

    static final Dimension PREFERRED_SIZE = new Dimension(900, 300);
    static final int DISPLAY_WIDTH = 60;

    public TChar(JFrame parent, KeyPair TManKP, KeyPair TCharKP, KeyPair TConsKP,
                KeyPair ServerKP, KeyPair CardKP, KeyPair ReCardKP) {
        super();

        TMan = TManKP;
        TChar = TCharKP;
        TCons = TConsKP;
        Server = ServerKP;
        Card = CardKP;
        ReCard = ReCardKP;

        T_TYPE = (byte) 0x02;
        T_SOFT_VERSION = (byte) 0;
        T_ID = new byte[] {(byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x02};

        //simulatorInterface = new JavaxSmartCardInterface(); // SIM
        buildGUI(parent);
        setEnabled(false);
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
        keypad = new JPanel(new GridLayout(7, 3));
        key("Read");
        key("Charge");
        key(null);

        key("Revoke");
        key("Rekey");
        key("Quit");

        key("7");
        key("8");
        key("9");

        key("4");
        key("5");
        key("6");

        key("1");
        key("2");
        key("3");

        key("Clear");
        key("0");
        key("Switch");

        key("Auth Buyer");
        key("Authenticate");
        key(null);
        add(keypad, BorderLayout.CENTER);
    }

    public void actionPerformed(ActionEvent ae) {
        try {
            Object src = ae.getSource();
            if (src instanceof JButton) {
                String s = ((JButton) src).getText();

                switch(s) {
                    case "Read": // read
                    case "Reset":
                        setText(readCard(T_TYPE, T_SOFT_VERSION, T_ID));
                        resetConnection();
                        break;
                    case "Authenticate": // authenticate
                        if(switchCallback.isRevokedCard(cardID)) {
                          setText("Revoked card");
                        } else {
                          setText(authenticate(T_TYPE, T_SOFT_VERSION, T_ID));
                        }
                        break;
                    case "Quit":
                        System.exit(0);
                        break;
                    case "Switch":
                        switchCallback.switchTerminal(T_TYPE);
                        break;
                    case "0":
                    case "1":
                    case "2":
                    case "3":
                    case "4":
                    case "5":
                    case "6":
                    case "7":
                    case "8":
                    case "9":
                        keyPressed(Integer.parseInt(s));
                        break;
                    case "Charge":
                    	setText(charge());
                    	break;
                    case "Revoke":
                        setText(revoke(T_TYPE, T_SOFT_VERSION));
                        break;
                    case "Rekey":
                        setText(rekey(T_TYPE, T_SOFT_VERSION, true, true, true, true));
                        break;
                    case "Clear":
                        setText("0");
                        pin = 0;
                        break;
                    case "Auth Buyer":
                        setText(authenticateBuyer(T_TYPE, T_SOFT_VERSION));
                        break;
                    default:
                        setText("nop");
                        resetConnection();
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(MSG_ERROR);
        }
    }

    void keyPressed(int key) {
        if (pin <= 99999) {
            pin *= 10;
            pin += key;
        } else {
            pin = 0;
        }
        setText(pin);
    }

    public String charge() {
        byte[] buffer = new byte[112];

        // TODO: reenable
        if (!authenticated || !buyerAuthenticated) {
            System.out.println("Authentication required before charging");
            return "Please authenticate first.";
        }

        incNonce(nonceT);
        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
        AESCipher.update(nonceT, (short) 0, (short) 8, buffer, (short) 0);
        AESCipher.doFinal(nonceC, (short) 0, (short) 8, buffer, (short) 0);

        CommandAPDU chargeCommand = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int)T_TYPE, (int)T_SOFT_VERSION, buffer, 0, 16, 64);
        ResponseAPDU response;
        try {
            response = applet.transmit(chargeCommand);
        } catch (CardException e) {
            return "Charging error";
        }

        byte[] data = response.getData();
        System.arraycopy(data, 0, cardID, 0, 4);

        short petrolQuota = Util.getShort(data, (short) 4);
        short tNum = Util.getShort(data, (short) 6);

        // Here we would verify the data given by the card with the server.

        signature.init(Card.getPublic(), Signature.MODE_VERIFY);
        signature.update(data, (short) 0, (short) 8);
        incNonce(nonceC);

        if(!signature.verify(nonceC, (short) 0, (short) 8, data, (short) 8, (short) 56)) {
            resetConnection();
            System.out.println("Sig failed 1");
            return "Charging failed, sig invalid";
        }
        short extraQuota = getMonthlyQuota(cardID);

        Util.setShort(data, (short) 4, extraQuota);
        Util.setShort(data, (short) 6, tNum);
        incNonce(nonceT);

        System.arraycopy(nonceT, 0, data, 8, 8);
        signature.init(TChar.getPrivate(), Signature.MODE_SIGN);
        signature.sign(data, (short) 0, (short) 16, data, (short) 8); // overwrites nonce (it is secret, so do not send in plaintext)

        chargeCommand = new CommandAPDU((int) PRFE_CLA, (int) CHAR_INS, (int) T_TYPE, (int) T_SOFT_VERSION, data, 0, 64, 112);
        try {
            response = applet.transmit(chargeCommand);
        } catch (CardException e) {
            return "Charging error";
        }

        data = response.getData();

        signature.init(Card.getPublic(), Signature.MODE_VERIFY);
        signature.update(cardID, (short) 0, (short) 4);
        signature.update(TCert, (short) 0, (short) 56);

        petrolQuota += extraQuota;
        Util.setShort(buffer, (short) 0, petrolQuota);
        Util.setShort(buffer, (short) 2, tNum);

        if (!signature.verify(buffer, (short) 0, (short) 4, data, (short) 0, (short) 56)) {
            System.out.println("Sig error 2");
            return "Charging error";
        }
        incNonce(nonceC);
        if (!signature.verify(nonceC, (short) 0, (short) 8, data, (short) 56, (short) 56)) {
            //return "Charging error";
            System.out.println("Sig error 3");
        }

        return "Charging successful!";
    }

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

    private short getMonthlyQuota(byte[] id) {
        return (short) 100;
    }

    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

}
