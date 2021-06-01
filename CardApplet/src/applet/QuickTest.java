package terminal;

import java.lang.System;

import javacard.framework.AID;
import javacard.framework.ISO7816;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

// imports for using JCardSim
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.licel.jcardsim.smartcardio.JCardSimProvider;

import applet.CardApplet;

/** Quick test of the Calculator applet using JCardSim's
 * JavaxSmartCardInterface which uses the Java's Smart Card I/O API,
 * aka javax.smartcard
 *
 * This
 *
 * javax.smartcard uses the CommandAPDU and ResponseAPDU classes for
 * sending and receiving APDUs, see
 * https://docs.oracle.com/javase/7/docs/jre/api/security/smartcardio/spec/javax/smartcardio/package-summary.html
 *
 * Beware: the code below and some of the samples on
 * https://jcardsim.org/docs/quick-start-guide-simulator-api only work
 * with JCardSim version 3.0.4, as they use the classes AIDUtil and
 * CardTerminalSimulator that are not included in jcardsim-2.2.*-all.jar
 *
 * @author erikpoll
 *
 */
public class QuickTest {

    static final byte[] CARD_APPLET_AID = { (byte) 0x3B, (byte) 0x29, (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };

    public static void main(String[] args){

      CommandAPDU command;
      //https://docs.oracle.com/javase/8/docs/jre/api/security/smartcardio/spec/javax/smartcardio/CommandAPDU.html
      ResponseAPDU response;


      // Create simulator
      JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();

      // Install applet
      AID cardAppletAID = new AID(CARD_APPLET_AID,(byte)0,(byte)7);
      simulator.installApplet(cardAppletAID, CardApplet.class);

      // Select applet
      CommandAPDU SELECT_APDU = new CommandAPDU( (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, CARD_APPLET_AID);
      System.out.println("Command APDU: " + SELECT_APDU.toString());
      System.out.println("Raw content of the command: " + toHexString(SELECT_APDU.getBytes()));

      response = simulator.transmitCommand(SELECT_APDU);
      System.out.println("Response APDU: " + response.toString());
      System.out.println("Raw content of the response: " + toHexString(response.getBytes())+"\n");


      // READ
      byte DATA[] = {1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
      byte CLA    = (byte) 0xB0;
      byte INS    = (byte) 0; //Instruction read 0x00
      byte TType  = (byte) 1; //Terminal type Card = 0x00, MAN = 0x01, CHAR = 0x02, CONS = 0x03
      byte TSV    = (byte) 1234; //Terminal Software Version
      byte LEN    = (byte) 8; //Length of the response
      command = new CommandAPDU(CLA, INS, TType, TSV, DATA, LEN);
      System.out.println("Command APDU: " + command.toString());
      System.out.println("Raw content of the command: " + toHexString(command.getBytes()));

      response = simulator.transmitCommand(command);
      System.out.println("Response APDU: " + response.toString());
      System.out.println("Raw content of the response: " + toHexString(response.getBytes())+"\n");


      // Press +
      /*command = new CommandAPDU(0, (int)'+', 0, 0, 5);
      System.out.println("Command APDU: " + command.toString());
      System.out.println("Raw content of the command: " + toHexString(command.getBytes()));

      response = simulator.transmitCommand(command);
      System.out.println("Response APDU: " + response.toString());
      System.out.println("Raw content of the response: " + toHexString(response.getBytes())+"\n");

      // Press =
      command = new CommandAPDU(0, (int)'=', 0, 0, 5);
      System.out.println("Command APDU: " + command.toString());
      System.out.println("Raw content of the command: " + toHexString(command.getBytes()));

      response = simulator.transmitCommand(command);
      System.out.println("Response APDU: " + response.toString());
      System.out.println("Raw content of the response: " + toHexString(response.getBytes())+"\n");*/
    }


    public static String toHexString(byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      for (byte b: bytes) {
        sb.append(String.format("%02X ", b));
      }
      return sb.toString();
    }
}
