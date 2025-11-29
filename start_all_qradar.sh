#!/bin/bash

# Copyright 2025 Palo Alto Networks, Inc.
# Released under Apache 2.0 license
# Paul Vinson - dl-qradar-data-export@paloaltonetworks.com
#
# Release 1.0


# This script will start all QRadar live processing.  Note: the ariel_dump.sh and process_arielClientdump.pl script
#  needs to be run on a system where QRadar is installed due to the need for the Java class files to operate.
#
# If you attempt to dump/process Ariel DB files on a live production system, you will bring down the ingestion/pipeline
#  processes as both cannot function due to the high load.
#
# So, make sure you either manually stop all the QRadar processes or run the compaion script stop_all_qradar.sh to 
#  do it for you. Upon reboot all these will autostart back up.

STARTLIST="imq postgresql-qvm hostcontext tomcat"

for ITEM in $STARTLIST
 do
	echo "Starting: $ITEM"
	systemctl start $ITEM
 done

