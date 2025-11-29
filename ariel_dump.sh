#!/bin/bash

# Copyright 2025 Palo Alto Networks, Inc.
# Released under Apache 2.0 license
# Paul Vinson - dl-qradar-data-export@paloaltonetworks.com
#
# Release 1.0

# Exit this script upon any errors
set -e

#  ************** Note ******************
#  There are no user-configurable settings in this script.  See next couple lines for details
#
#  These processes need to be run on a live QRadar system with all production processes stopped other than PostGreSQL
#  Read the documentation for details

#  All variables are stored in one of two settings files.   Both of these are located where this script lives.
#  Everything defined in the two(2) settings files can point to other locations, etc.
#
#  1) static_settings_ariel_dump.config  - where all things configuration go or
#  2) dynamic_settings_ariel_dump.config - where settings go that could affect live operation of these scripts, i.e., changing concurrency mid-flight

# Get the directory name where this script is at, which gives us maximum flexiblity from where to execute (locally as in ./script.sh or absolute path as in /opt/scripts/script.sh)
# 
EXECUTION_DIRECTORY=$(dirname "$(readlink -f "$0")")

# Record the start time for logging/reporting purposes
SCRIPT_START_TIME=$(date)

# Load up the stuff and set the QRadar system variables that the Ariel Dump Client needs
#
. /opt/qradar/systemd/bin/functions.qradar
PATH=$PATH:$JAVA_HOME/bin
JARS_DIR=$NVA/jars
for JAR in $(find $JARS_DIR/ -iname "*.jar")
do
        CLASSPATH=$CLASSPATH:$JAR
done

#
# Load up stuff and set the variables that this parent process and any needs of children processes
. ${EXECUTION_DIRECTORY}/static_settings_ariel_dump.config

# Exit if key variables are not set from ${EXECUTION_DIRECTORY}/static_settings_ariel_dump.config
#
if [[ -z "$START_DATE" || -z "$END_DATE" || -z "$BASEDIR" || -z "$CONVERTED_DATA_DESTINATION" || -z "$TMPDIR" || -z "$LOGFILE" ]]

   then
	echo "At least one variable is needs to be configured at ${EXECUTION_DIRECTORY}/static_settings_ariel_dump.config"
	exit
   fi

exit

# Log the beginning of this job
#
printf "%s\tStarting job with start date: ${START_DATE}\tend date: ${END_DATE}\n" "$(date)" >> $LOGFILE


# Let's get a list of the Ariel records (down to the minute) we are going to be working with and then
#  shuffle the list to potentially spread out disk i/o
#
ARIEL_RECORD_LIST=$(
	while [[ "$START_DATE" != "$END_DATE" ]]
	 do
		START_DATE=$(date --date "$START_DATE + 1 day" +"%Y/%-m/%-d")
		find /store/ariel/events/records/${START_DATE}/ -name events* -type f 2>/dev/null
	 done | sort -R > /tmp/ariel_dump.$$; cat /tmp/ariel_dump.$$)
	 #done | sort -R > /tmp/ariel_dump.$$; cat /tmp/ariel_dump.$$; rm -f /tmp/ariel_dump.$$)

# Get job size and store it for later use
#
ARIEL_RECORD_LIST_SIZE=$(printf '%s\n' "${ARIEL_RECORD_LIST[@]}" | wc -l)

# Initialize variable to track loop count
LOOP_COUNT=0

# Loop through and get the job done
#
for ARIEL_RECORD in $ARIEL_RECORD_LIST
 do
	LOOP_COUNT=$((LOOP_COUNT+1))

	printf "%s\tWorking with Ariel record $LOOP_COUNT of $ARIEL_RECORD_LIST_SIZE = $(printf %.2f $(echo "scale=4; ($LOOP_COUNT / $ARIEL_RECORD_LIST_SIZE) * 100" | bc))%% job complete: $ARIEL_RECORD\n" "$(date)" >> $LOGFILE

	JOB_ENGAGED=no

	while [ "$JOB_ENGAGED" = "no" ]
	      do

		. ${BASEDIR}/dynamic_settings_ariel_dump.config

		CURRENT_JOBS_RUNNING=$(ps -ef | grep 'com.q1labs.cve.utils.CommandLineClient' | grep -v grep | wc -l)
		#CURRENT_JOBS_RUNNING=1

		printf "%s\t Current number of Ariel Dump Client jobs running: $CURRENT_JOBS_RUNNING\n" "$(date)" >> $LOGFILE

		if [ "$CURRENT_JOBS_RUNNING" -lt "$CONCURRENT_ARIEL_DUMP_JOBS" ]
		   then

			printf "%s\t Kicking off new Ariel Dump Client process with $CONCURRENT_DATA_CONVERSION_JOBS children perl processes\n" "$(date)" >> $LOGFILE

        		java -Dlog4j.configuration=/opt/qradar/conf/log4j2.xml \
				-cp $CLASSPATH \
				-Xmx128m \
				-Dapplication.baseURL=file:///opt/qradar/conf/ \
				com.q1labs.cve.utils.CommandLineClient "--dump" \
				$ARIEL_RECORD 2>/dev/null |\
				parallel -j$CONCURRENT_DATA_CONVERSION_JOBS --pipe --round-robin --tmpdir $TMPDIR \
					--block 5M --recstart 'com.q1labs' --recend '\n' \
					${BASEDIR}/process_arielClientdump.pl $BASEDIR $CONVERTED_DATA_DESTINATION &
		
			# New job started, let's bust out of this loop and take a look at the next event file to be processed
			JOB_ENGAGED=yes

		   else

			random_number=$((2 + RANDOM % 5))
			printf "%s\t Maximum number of concurrent jobs ($CONCURRENT_ARIEL_DUMP_JOBS) already reached.  Pausing for $random_number seconds\n" "$(date)" >> $LOGFILE
			sleep $random_number

		   fi
		

	      done # 'end of while [ "$JOB_ENGAGED" = "no" ]

 done # 'end of for ARIEL_RECORD in $ARIEL_RECORD_LIST

printf "%s\tAll event files processed, waiting for jobs to finish\n" "$(date)" >> $LOGFILE
wait

printf "%s\tAll jobs finished for start date: ${START_DATE}\t-\tend date: ${END_DATE}\n" "$(date)" >> $LOGFILE
printf "%s\tThis processing job started at $SCRIPT_START_TIME and ended at %s\n" "$(date)" "$(date)" >> $LOGFILE
