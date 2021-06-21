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
    private static final byte CONS_INS = (byte) 0x30;
    private static final int CONSUME_LIMIT = 2000;
    private static final short NONCET_LENGTH  = 8;
    private static final short SIGN_LENGTH = 56;


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

    public void resetConnection() {
        super.resetConnection();
        resetSession();
    }

    private void resetSession() {
        consumeAmount = 0;
        setText("Enter the amount you would like to consume:");
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
        keypad = new JPanel(new GridLayout(6, 3));
        key("Read");
        key("Consume");
        key("Authenticate");

        key("Revoke");
        key("Rekey");

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
                        if(switchCallback.isRevokedCard(cardID)) {
                          setText("Revoked card");
                        } else {
                          setText(authenticate(T_TYPE, T_SOFT_VERSION, T_ID));
                          resetSession();
                        }
                        break;
                    case "Quit":
                        System.exit(0);
                        break;
                    case "Switch":
                        switchCallback.switchTerminal(T_TYPE);
                        resetConnection();
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
                        //consumeQuota();
                        setText(consumeQuota());
                      //  resetSession();
                        break;
                    case "Revoke":
                        setText(revoke(T_TYPE, T_SOFT_VERSION));
                        break;
                    case "Rekey":
                        setText(rekey(T_TYPE, T_SOFT_VERSION, true, true, true, true));
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

   public String consumeQuota(){                                                        //use an amount of petrol quota on the card
        //send sequence number to card to start the consumption transaction
       byte[] sigBuffer = new byte[112];

       System.arraycopy(nonceT, 0, sigBuffer, 0, 8);
       System.arraycopy(nonceT, 0, sigBuffer, 8, 8);
       AESCipher.init(skey, Cipher.MODE_ENCRYPT);
       AESCipher.doFinal(sigBuffer, (short) 0, (short) 16, sigBuffer, (short) 0);

       CommandAPDU consumeCommand = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int)T_TYPE, (int)T_SOFT_VERSION, sigBuffer);
       ResponseAPDU response;
       try {
           response = applet.transmit(consumeCommand);
       } catch (CardException e) {
           return "Transmission error";
       }

        byte[] data = response.getData();
        System.out.println(response.getNr()); //card successfully returns 64 bits of data now

       System.arraycopy(data, 0, cardID, 0, 4);
       System.out.println(Arrays.toString(cardID));

       short petrolQuotaOnCard = Util.getShort(data, (short) 4);
       System.out.println(petrolQuotaOnCard);

       short tNum = Util.getShort(data, (short) 6);
       System.out.println(tNum);

       signature.init(Card.getPublic(), Signature.MODE_VERIFY);
       signature.update(data, (short) 0, (short) 8);
       incNonce(nonceT);
       System.out.println("hello"); // everything up to this point works for the consumption, only the signature does not verify so it will not run the rest.

//       if(!signature.verify(nonceT, (short) 0, (short) 8, data, (short) 0, (short) 56)) {
//          // resetConnection();
//           return "Consumption failed, sig invalid";
//       }

       short amount = (short) consumeAmount;
       System.out.println(amount);


        if (amount > CONSUME_LIMIT){
            return "Requested amount larger than maximum value";
        }
        else if (petrolQuotaOnCard - amount < 0){
            return "Insufficient petrol credits left";
        }
       short wantedPetrol = (short) (petrolQuotaOnCard - amount);

       data[4] = (byte) (wantedPetrol & 0xff);
       data[5] = (byte) ((wantedPetrol >> 8) & 0xff);

       data[6] = (byte) (tNum & 0xff);
       data[7] = (byte) ((tNum >> 8) & 0xff);
       incNonce(nonceT);

       System.arraycopy(nonceT, 0, data, 8, 8);
       signature.init(TCons.getPrivate(), Signature.MODE_SIGN);
       signature.sign(data, (short) 0, (short) 16, data, (short) 8);

       consumeCommand = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) T_TYPE, (int)T_SOFT_VERSION, data);
       try {
           response = applet.transmit(consumeCommand);
       } catch (CardException e) {
           return "Charging error";
       }

       data = response.getData();
       System.out.println(response.getNr());
       incNonce(nonceT);

       if(data[0] == (byte) 0) {
           short remainingPetrolQuota = getGasUsed(amount, petrolQuotaOnCard);
           if (remainingPetrolQuota < wantedPetrol) {

               short updatedQuota = (short) (wantedPetrol - remainingPetrolQuota);


               System.arraycopy(cardID, 0, sigBuffer, 0, 4);
               Util.setShort(sigBuffer, (short) 4, updatedQuota);
               System.arraycopy(nonceT, 0, sigBuffer, 6, NONCET_LENGTH);
               Util.setShort(sigBuffer, (short) 14, tNum);


               AESCipher.init(skey, Cipher.MODE_ENCRYPT);
               AESCipher.doFinal(sigBuffer, (short) 0, (short) 16, sigBuffer, (short) 6);

               CommandAPDU cons3Command = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) T_TYPE, (int) T_SOFT_VERSION, sigBuffer);

               ResponseAPDU response3;
               try {

                   response3 = applet.transmit(cons3Command);
               } catch (CardException e) {
                   System.out.println(e);
                   return "Transmit error";
               }
           }
       }



//        System.arraycopy(cardID, 0, sigBuffer, 0, 4);
//        Util.setShort(sigBuffer, (short) 4, petrolQuotaOnCard);
//        System.arraycopy(nonceC, 0, sigBuffer, 6, NONCET_LENGTH);
//        Util.setShort(sigBuffer, (short) 14, (short) 0); //make data 16 bytes, could also use tnum?
//
//        AESCipher.init(skey, Cipher.MODE_DECRYPT);
//        AESCipher.doFinal(data, (short) 6, (short) SIGN_LENGTH, sigBuffer, (short) 16);
//        if ((Util.arrayCompare(sigBuffer, (short) 0, sigBuffer, (short) 14, (short) 14)) != (byte) 0) {
//            return "Signature invalid";
//        }
//
//        short amount = (short) consumeAmount;
//
//        if (amount > CONSUME_LIMIT){
//            return "Requested amount larger than maximum value";
//        }
//        else if (petrolQuotaOnCard - amount < 0){
//            return "Insufficient petrol credits left";
//        }
//
//        short wantedPetrol = (short) (petrolQuotaOnCard - amount);
//        incNonce(nonceC); //sequence nr + 2
//        nonceT = nonceC;
//
//        byte[] dataBuffer = new byte[16];
//        System.arraycopy(cardID, 0, dataBuffer, 0, 4);
//        Util.setShort(dataBuffer, (short) 4, wantedPetrol);
//        System.arraycopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);
//        Util.setShort(dataBuffer, (short) 14, (short) 0);
//
//
//
//        AESCipher.init(skey, Cipher.MODE_ENCRYPT);
//        AESCipher.doFinal(dataBuffer, (short) 0, (short) 16, sigBuffer, (short) 6);
//
//        CommandAPDU cons2Command = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) T_TYPE, (int) T_SOFT_VERSION, sigBuffer);
//
//        ResponseAPDU response2;
//        try {
//            response2 = applet.transmit(cons2Command);
//        } catch (CardException e) {
//            System.out.println(e);
//            return "Transmit error";
//        }
//        incNonce(nonceT); //sequence nr + 3
//        nonceC = nonceT;
//        incNonce(nonceC); //sequence nr + 4
//        nonceT = nonceC;
//        byte[] responseData = response2.getData();
//        if(responseData[0] == (byte) 0){
//            short remainingPetrolQuota = getGasUsed(amount, petrolQuotaOnCard);
//            if(remainingPetrolQuota < wantedPetrol){
//
//                short updatedQuota = (short) (wantedPetrol - remainingPetrolQuota);
//
//                System.arraycopy(cardID, 0, dataBuffer, 0, 4);
//                Util.setShort(dataBuffer, (short) 4,  updatedQuota);
//                System.arraycopy(nonceT, 0, dataBuffer, 6, NONCET_LENGTH);
//                Util.setShort(dataBuffer, (short) 14, (short) 0);
//
//
//                AESCipher.init(skey, Cipher.MODE_ENCRYPT);
//                AESCipher.doFinal(dataBuffer, (short) 0, (short) 16, sigBuffer, (short) 6);
//
//                CommandAPDU cons3Command = new CommandAPDU((int) PRFE_CLA, (int) CONS_INS, (int) T_TYPE, (int)T_SOFT_VERSION, sigBuffer);
//
//                ResponseAPDU response3;
//                try {
//
//                    response3 = applet.transmit(cons3Command);
//                } catch (CardException e) {
//                    System.out.println(e);
//                    return "Transmit error";
//                }
//            }
//        }
        return "Successful transaction";
    };


    short getGasUsed(short amount, short remainingPetrolQuota){
        short temporaryQuota = remainingPetrolQuota;
        for(int i = 0; i < amount; i++){
            System.out.print("Dispensing petrol....");
            temporaryQuota -= 1; //reduce the remaining quota by 1, one step at a time, this should eventually equal
            // petrolQuotaOnCard - amount, if not then we deal with this in terminal
        }
        return temporaryQuota;
    };

    public byte[] generateNonce(){
        //generate a 32 bit random nonce
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[NONCET_LENGTH];
        random.nextBytes(bytes);
        return bytes;
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
    };



    public Dimension getPreferredSize() {
        return PREFERRED_SIZE;
    }

}
