#!/bin/bash

echo "Hurray, lets test our PRFE apdu of epicness :D"
echo "Make sure to put the test apdu in test.apdu in the same folder as this script."

java -classpath util/jcardsim/jcardsim-2.2.1-all.jar:CardApplet/bin com.licel.jcardsim.utils.APDUScriptTool util/jcardsim/jcardsim.cfg test.apdu
