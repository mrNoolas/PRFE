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

public class TCons extends PRFETerminal {
    private static final byte PERS_INS = (byte) 0x50;
    private static final int CONSUME_LIMIT = 2000;

    static final Dimension PREFERRED_SIZE = new Dimension(900, 300);
    static final int DISPLAY_WIDTH = 60;

    int consumeAmount = 0;


    public TCons(JFrame parent, KeyPair TManKP, KeyPair TCharKP, KeyPair TConsKP,
                KeyPair ServerKP, KeyPair CardKP, KeyPair ReCardKP) {
        super();

        TMan = TManKP;
        TChar = TCharKP;
        TCons = TConsKP;
        Server = ServerKP;
        Card = CardKP;
        ReCard = ReCardKP;

        T_TYPE = (byte) 0x03;
        T_SOFT_VERSION = (byte) 0;
        T_ID = new byte[] {(byte) 0x03, (byte) 0x03, (byte) 0x03, (byte) 0x03};

        buildGUI(parent);
        setEnabled(false);
        resetConnection();
    }

    void resetConnection() {
        super.resetConnection();
        resetSession();
    }

    void resetSession() {
        consumeAmount = 0;
        setText("Enter the amount you would like to consume:")
    }

    void keyPressed(int key) {
        if (consumeAmount < CONSUME_LIMIT * 10) {
            consumeAmount *= 10;
            consumeAmount += key;
        } else {
            consumeAmount = 0;
        }
        setText(consumeAmount);
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
        keypad = new JPanel(new GridLayout(5, 3));
        key("Read");
        key("Consume");
        key("Authenticate");

        key("7");
        key("8");
        key("9");

        key("4");
        key("5");
        key("6");

        key("1");
        key("2");
        key("3");

        key("Quit");
        key("0");
        key("Switch");
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
                        resetConnection();
                        setText(readCard(T_TYPE, T_SOFT_VERSION, T_ID));
                        break;
                    case "Authenticate": // authenticate
                        setText(authenticate(T_TYPE, T_SOFT_VERSION, T_ID));
                        resetSession();
                        break;
                    case "Quit":
                        System.exit(0);
                        break;
                    case "Switch":
                        switchCallback.switchTerminal(T_TYPE);
                        resetTerminal();
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
                    case "Consume":
                        consumeQuota();
                        resetSession();
                        break;
                    case "Revoke":
                    case "Rekey":
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

    public String consumeQuota(){                                                        //use an amount of petrol quota on the card
        //send sequence number to card to start the consumption transaction
        byte[] nonceT = generateNonce();
        byte[] sigBuffer = new byte[2*SIGN_LENGTH];

        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(nonceT, (short) 0, (short) 8, sigBuffer, (short) 0);
        CommandAPDU consumeCommand = new CommandAPDU(PRFE_CLA, CONS_INS, T_TYPE, T_SOFT_VERSION, sigBuffer);

        ResponseAPDU response = null;
        try {
            //card sends back apdu with the data after transmitting the commandAPDU to the card
            response = applet.transmit(consumeCommand);
        } catch (CardException e) {
            // TODO: do something with the exception
            System.out.println(e);
            return "Transmit error";
        }

        //verify response
        byte[] data = response.getData();
        //data = card-id, quota, signedData
        byte[] cardID = new byte[4];
        Util.arrayCopy(data, (short) 0, cardID, (short) 0, (short) 4);
        short petrolQuotaOnCard = Util.getShort(data, (short) 4);
        incNonce(nonceT); //sequence nr + 1
        byte[] nonceC = nonceT;

        System.arraycopy(cardID, 0, sigBuffer, 0, 4);
        Util.setShort(sigBuffer, (short) 4, petrolQuotaOnCard);
        System.arraycopy(nonceC, 0, sigBuffer, 6, NONCET_LENGTH);

        signature.init(skey, Signature.MODE_VERIFY);
        if (!signature.verify(sigBuffer, (short) 0, (short) 14, data, (short) 6, SIGN_LENGTH)) {
            return "Signature invalid";
        }

        short amount = 0;
        //amount = entered by the buyer

        //TODO: read input and put this value into short amount
        char[] inputAmount = new char[5]; //max value for short amounts is a 5 digit number, so input cant be more than that
        //read input characters
        //parse char[] as short -> inputamount as a string, then parseShort (string);
        //if amount > Short.MAX_VALUE: return error -> amount exceeds maximum


        //buffer for key listener and read in from that?
        //card has quota balance, if amount is larger than this, return error
        if (petrolQuotaOnCard - amount < 0){
            return "Insufficient petrol credits left";
        }
        else if (amount > maxGas){
            return "Requested amount larger than maximum value";
        }
        //if quota on card - amount < 0 : exit
        short wantedPetrol = (short) (petrolQuotaOnCard - amount);
        incNonce(nonceC); //sequence nr + 2
        nonceT = nonceC;

        byte[] dataBuffer = new byte[14];
        System.arraycopy(cardID, 0, dataBuffer, 0, 4);
        Util.setShort(dataBuffer, (short) 4, wantedPetrol);
        System.arraycopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);


        signature.init(skey, Signature.MODE_SIGN);
        signature.sign(dataBuffer, (short) 0, (short) 14, sigBuffer, (short) 6);

        CommandAPDU cons2Command = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, sigBuffer);

        ResponseAPDU response2;
        try {
            response2 = applet.transmit(cons2Command);
        } catch (CardException e) {
            System.out.println(e);
            return "Transmit error";
        }
        incNonce(nonceT); //sequence nr + 3
        nonceC = nonceT;
        incNonce(nonceC); //sequence nr + 4
        nonceT = nonceC;
        byte[] responseData = response2.getData();
        if(responseData[0] == (byte) 1){
            setMaxGas(amount);
            short remainingPetrolQuota = getGasUsed(amount, petrolQuotaOnCard);
            if(remainingPetrolQuota < wantedPetrol){

                short updatedQuota = (short) (wantedPetrol - remainingPetrolQuota);

                System.arraycopy(cardID, 0, dataBuffer, 0, 4);
                Util.setShort(dataBuffer, (short) 4,  updatedQuota);
                System.arraycopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);


                System.arraycopy(cardID, 0, sigBuffer, 0, 4);
                Util.setShort(sigBuffer, (short) 4, updatedQuota);
                System.arraycopy(signedData, 0, sigBuffer, 6, SIGN_LENGTH);


                signature.init(skey, Signature.MODE_SIGN);
                signature.sign(dataBuffer, (short) 0, (short) 14, sigBuffer, (short) 6);

                CommandAPDU cons3Command = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) TERMINAL_TYPE, (int)TERMINAL_SOFTWARE_VERSION, sigBuffer);

                ResponseAPDU response3;
                try {

                    response3 = applet.transmit(cons3Command);
                } catch (CardException e) {
                    //TODO: do something with the exception
                    System.out.println(e);

                    return "Transmit error";
                }
            }
        }

    };

    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

}
