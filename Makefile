# Path to the Java Card Development Kit
JC_HOME=util/java_card_kit-2_2_1

# Version of JCardSim to use;
JCARDSIM=jcardsim-3.0.4-SNAPSHOT

# Beware that only JCardSim-3.0.4-SNAPSHOT.jar includes the classes
# AIDUtil and CardTerminalSimulator, so some of the code samples on
# https://jcardsim.org/docs do not work with older versions
#    JCARDSIM=jcardsim-2.2.1-all
#    JCARDSIM=jcardsim-2.2.2-all

# Classpath for JavaCard code, ie the smartcard applet; this includes
# way more than is probably needed
JC_CLASSPATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

all: applet TerminalSwitch PRFETerminal TManTerminal TCharTerminal TConsTerminal TermSim

runTerminals: all run

# ===== Card =====
applet: CardApplet/bin/CardApplet.class

CardApplet/bin/CardApplet.class: CardApplet/src/applet/CardApplet.java
	javac -d CardApplet/bin -cp ${JC_CLASSPATH}:TMan/src CardApplet/src/applet/CardApplet.java

CardQuickTest: CardApplet/bin/QuickTest.class

CardApplet/bin/QuickTest.class: CardApplet/src/applet/QuickTest.java
	javac -d CardApplet/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin CardApplet/src/applet/QuickTest.java

runCardQuickTest: CardQuickTest
	java -cp util/jcardsim/${JCARDSIM}.jar:CardApplet/bin terminal.QuickTest


# ===== QuickTest =====
TManQuicktest: TMan/bin/terminal/QuickTest.class

TMan/bin/terminal/QuickTest.class: TMan/src/terminal/QuickTest.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin TMan/src/terminal/QuickTest.java

runTManQuicktest:
	# Sends some sample APDUs to the CalcApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:CalcTerminal/bin:TMan/bin terminal.QuickTest

# ===== Terminals =====
TMan: TMan/bin/terminal/TMan.class
TermSim: TMan/bin/terminal/TermSim.class
PRFETerminal: TMan/bin/terminal/PRFETerminal.class
TerminalSwitch: TMan/bin/terminal/TerminalSwitch.class
TManTerminal: TMan/bin/terminal/TMan.class
TCharTerminal: TMan/bin/terminal/TChar.class
TConsTerminal: TMan/bin/terminal/TCons.class

TMan/bin/terminal/TermSim.class: TMan/src/terminal/TermSim.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TermSim.java

TMan/bin/terminal/TerminalSwitch.class: TMan/src/terminal/TerminalSwitch.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TerminalSwitch.java

TMan/bin/terminal/PRFETerminal.class: TMan/src/terminal/PRFETerminal.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/PRFETerminal.java

TMan/bin/terminal/TMan.class: TMan/src/terminal/TMan.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TMan.java

TMan/bin/terminal/TChar.class: TMan/src/terminal/TChar.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TChar.java

TMan/bin/terminal/TCons.class: TMan/src/terminal/TCons.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TCons.java

run:
	# Runs the GUI terminal
	java -Djdk.sunec.disableNative=false -cp util/jcardsim/${JCARDSIM}.jar:TMan/bin:CardApplet/bin terminal.TermSim

clean:
	rm -rf CardApplet/bin/*
	rm -rf TMan/bin/*
