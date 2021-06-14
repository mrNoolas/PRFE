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

all: applet PRFETerminal TermSim TManTerminal TCharTerminal TermSim runTerminals #TCharTerminal TConsTerminal TMan TChar TCons

applet: CardApplet/bin/CardApplet.class

CardApplet/bin/CardApplet.class: CardApplet/src/applet/CardApplet.java
	javac -d CardApplet/bin -cp ${JC_CLASSPATH}:TMan/src CardApplet/src/applet/CardApplet.java

CardQuickTest: CardApplet/bin/QuickTest.class

CardApplet/bin/QuickTest.class: CardApplet/src/applet/QuickTest.java
	javac -d CardApplet/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin CardApplet/src/applet/QuickTest.java

runCardQuickTest: CardQuickTest
	java -cp util/jcardsim/${JCARDSIM}.jar:CardApplet/bin terminal.QuickTest


# ===== TMan =====
TManQuicktest: TMan/bin/terminal/QuickTest.class

TMan/bin/terminal/QuickTest.class: TMan/src/terminal/QuickTest.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin TMan/src/terminal/QuickTest.java

runTManQuicktest:
	# Sends some sample APDUs to the CalcApplet
	java -cp util/jcardsim/${JCARDSIM}.jar:CalcTerminal/bin:TMan/bin terminal.QuickTest

TMan: TMan/bin/terminal/TMan.class

TermSim: TMan/bin/terminal/TermSim.class

TMan/bin/terminal/TermSim.class: TMan/src/terminal/TermSim.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TermSim.java

PRFETerminal: TMan/bin/terminal/PRFETerminal.class

TMan/bin/terminal/PRFETerminal.class: TMan/src/terminal/PRFETerminal.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/PRFETerminal.java

TManTerminal: TMan/bin/terminal/TMan.class

TMan/bin/terminal/TMan.class: TMan/src/terminal/TMan.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TMan.java

TCharTerminal: TMan/bin/terminal/TChar.class

TMan/bin/terminal/TChar.class: TMan/src/terminal/TChar.java
	javac -d TMan/bin -cp ${JC_HOME}:util/jcardsim/${JCARDSIM}.jar:CardApplet/bin:TMan/bin TMan/src/terminal/TChar.java

runTerminals:
	# Runs the GUI terminal
	java -Djdk.sunec.disableNative=false -cp util/jcardsim/${JCARDSIM}.jar:TMan/bin:CardApplet/bin terminal.TermSim




clean:
	rm -rf CardApplet/bin/*
	rm -rf TMan/bin/*
