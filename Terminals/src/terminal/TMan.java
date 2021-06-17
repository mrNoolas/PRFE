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


public class TMan extends PRFETerminal {
    private static final byte PERS_INS = (byte) 0x50;

    static final Dimension PREFERRED_SIZE = new Dimension(900, 150);
    static final int DISPLAY_WIDTH = 60;

    public TMan(JFrame parent, KeyPair TManKP, KeyPair TCharKP, KeyPair TConsKP,
                KeyPair ServerKP, KeyPair CardKP, KeyPair ReCardKP) {
        super();

        TMan = TManKP;
        TChar = TCharKP;
        TCons = TConsKP;
        Server = ServerKP;
        Card = CardKP;
        ReCard = ReCardKP;

        T_TYPE = (byte) 0x01;
        T_SOFT_VERSION = (byte) 0;
        T_ID = new byte[] {(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01};

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
        keypad = new JPanel(new GridLayout(2, 4));
        key("Read");
        key("Personalise");
        key("Authenticate");
        key("Quit");
        key("Switch");
        key("Revoke");
        key("Rekey");
        key("Reset");
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
                        setText(authenticate(T_TYPE, T_SOFT_VERSION, T_ID));
                        break;
                    case "Personalise":
                        setText(personalise());
                        resetConnection();
                        break;
                    case "Quit":
                        System.exit(0);
                        break;
                    case "Switch":
                        switchCallback.switchTerminal(T_TYPE);
                        resetConnection();
                        break;
                    case "Revoke":
                        setText(revoke(T_TYPE, T_SOFT_VERSION));
                        break;
                    case "Rekey":
                    default:
                        setText("nop"); //sendKey((byte) c));
                        resetConnection();
                        break;
                }
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(MSG_ERROR);
        }
    }

    public String personalise () {
        byte[] buffer0 = new byte[228];
        byte[] buffer1 = new byte[172];

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


    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

}
