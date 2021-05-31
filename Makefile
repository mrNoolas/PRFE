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

all: applet TManTerminal TCharTerminal TConsTerminal TMan TChar TCons

applet: CardApplet/bin/CardApplet.class

CardApplet/bin/CardApplet.class: CardApplet/src/applet/CardApplet.java
	javac -d CardApplet/bin -cp ${JC_CLASSPATH}:TMan/src CardApplet/src/applet/CardApplet.java

CardQuickTest: CardApplet/bin/QuickTest.class

CardApplet/bin/QuickTest.class: CardApplet/src/applet/QuickTest.java
	javac -d CardApplet/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin CardApplet/src/applet/QuickTest.java

runCardQuickTest:
	java -cp util/jcardsim/${JCARDSIM}.jar:CardApplet/bin terminal.QuickTest


# ===== TMan =====
TMan: TMan/bin/terminal/QuickTest.class

TMan/bin/terminal/QuickTest.class: TMan/src/terminal/QuickTest.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin TMan/src/terminal/QuickTest.java

runTMan:
	# Sends some sample APDUs to the CardApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:TMan/bin:CardApplet/bin terminal.QuickTest

TManTerminal: TMan/bin/terminal/TMan.class

TMan/bin/terminal/TMan.class: TMan/src/terminal/TMan.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TMan.java

runTManTerminal:
	# Runs the GUI terminal
	java -cp util/jcardsim/${JCARDSIM}.jar:TMan/bin:CardApplet/bin terminal.TMan


# ===== TCons =====
TCons: TCons/bin/terminal/QuickTest.class

TCons/bin/terminal/QuickTest.class: TCons/src/terminal/QuickTest.java
	javac -d TCons/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin TCons/src/terminal/QuickTest.java

runTCons:
	# Sends some sample APDUs to the CardApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:TCons/bin:CardApplet/bin terminal.QuickTest

TConsTerminal: TCons/bin/terminal/TCons.class

TCons/bin/terminal/TCons.class: TCons/src/terminal/TCons.java
	javac -d TCons/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TCons/bin TCons/src/terminal/TCons.java

runTConsTerminal:
	# Runs the GUI terminal
	java -cp util/jcardsim/${JCARDSIM}.jar:TCons/bin:CardApplet/bin terminal.TCons

# ===== TChar =====
TChar: TChar/bin/terminal/QuickTest.class

TChar/bin/terminal/QuickTest.class: TChar/src/terminal/QuickTest.java
	javac -d TChar/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin TChar/src/terminal/QuickTest.java

runTChar:
	# Sends some sample APDUs to the CardApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:TChar/bin:CardApplet/bin terminal.QuickTest

TCharTerminal: TChar/bin/terminal/TChar.class

TChar/bin/terminal/TChar.class: TChar/src/terminal/TChar.java
	javac -d TChar/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TChar/bin TChar/src/terminal/TChar.java

runTCharTerminal:
	# Runs the GUI terminal
	java -cp util/jcardsim/${JCARDSIM}.jar:TChar/bin:CardApplet/bin terminal.TChar

clean:
	rm -rf CardApplet/bin/*
	rm -rf TMan/bin/*
	rm -rf TChar/bin/*
	rm -rf TCons/bin/*
