#!/usr/bin/perl

# Copyright 2025 Palo Alto Networks, Inc.
# Released under Apache 2.0 license
# Paul Vinson - dl-qradar-data-export@paloaltonetworks.com
#
# Release 1.0

use DBI;

# select qid, qname, qdescription from qidmap


# So this script needs to be ran a QRadar appliance from customer deployment that has postgresql running
#
#

# Instructions:  Modify the two variables below to designate where to place the output files.   These
# 		  files will be needed to sucessfully parse the Ariel dump files by the perl
#		  script: process_arielClientdump.pl

#
# Designate the place to write the output file that contains the log source / log source mappings
# The below two examples will either let you set an absolute path, or look for it in the current directory
#$log_source_mappings = "/root/scripts/process_ariel_dump/log_source_mappings.out";
$log_source_mappings = "./log_source_mappings.out";

#
# Designate the place to write the output file that contains the qid mappings
# The below two examples will either let you set an absolute path, or look for it in the current directory
#$qid_mappings = "/root/scripts/process_ariel_dump/qid_mappings.out";
$qid_mappings = "./qid_mappings.out";

#
# No user tunable parameters below this line
#
#
###################################################################
#
# Set debug to true for more info
#
#
#$debug = true;

# Set all the traditional QRadar defaults.   These should apply on all vanilla QRadar deployments and will suffice
#  in virtually all conceivable deployments
my $driver   = "Pg"; 
my $database = "qradar";
my $dsn = "DBI:$driver:dbname = $database;host = 127.0.0.1;port = 5432";
my $userid = "qradar";
my $password = "";
my %logsource;
my %sensordevices;
my %sensordevicetypes;

# Open up the QRadar Postgresql database for read
#
#
my $dbHand = DBI->connect("dbi:Pg:dbname=qradar;", "qradar", "") or die "Can't connect to postgres db: $!\n";


# Load up a hash array of log sources from the postgresql sensordevice table
#
#
my $stmt = qq(SELECT id,devicename,devicetypeid from sensordevice;);
my $sth = $dbHand->prepare( $stmt );
my $rv = $sth->execute() or die $DBI::errstr;
if($rv < 0) {
   print $DBI::errstr;
}

while(my @row = $sth->fetchrow_array()) {

	$device_id = $row[0];
	$sensordevices{$device_id}->[1] = $row[1];  # sensordevice devicename
	$sensordevices{$device_id}->[2] = $row[2];  # sensordevice devicetypeid
}


# Load up a hash array of log source device types from the postgresql sensordevicetype table
#
#
my $stmt = qq(select id,devicetypename,devicetypedescription from sensordevicetype;);
my $sth = $dbHand->prepare( $stmt );
my $rv = $sth->execute() or die $DBI::errstr;
if($rv < 0) {
   print $DBI::errstr;
}

while(my @row = $sth->fetchrow_array()) {
 
 	$devicetype_id = $row[0];  # devicetypeid
 	$devicetypes{$devicetype_id}->[1] = $row[1];  # devicetypename
 	$devicetypes{$devicetype_id}->[2] = $row[2];  # devicetypedescription
}


# Merge the two hash arrays into a new single, complete, hash array and save a copy
#
#
open(LOG_SOURCE_MAPPINGS, '>', $log_source_mappings) or die $!;
@sensordeviceid = keys ( %sensordevices );
foreach $device_id ( @sensordeviceid ) {

	$logsource_id{$device_id}->[0] = $device_id;						# Log source ID
	$logsource_id{$device_id}->[1] = $sensordevices{$device_id}->[1];			# Log source name
	$logsource_id{$device_id}->[2] = $sensordevices{$device_id}->[2];			# Log source devicetype ID
	$logsource_id{$device_id}->[3] = $devicetypes{ $sensordevices{$device_id}->[2] }->[1];	# Log source devicetype name
	$logsource_id{$device_id}->[4] = $devicetypes{ $sensordevices{$device_id}->[2] }->[2];	# Log source devicetype description

	print LOG_SOURCE_MAPPINGS "$logsource_id{$device_id}->[0],$logsource_id{$device_id}->[1],$logsource_id{$device_id}->[2],$logsource_id{$device_id}->[3],$logsource_id{$device_id}->[4]\n";

	# Here we test if we can read the copy of the unified hash of arrays from memory
	if ($debug) {
		print "Log source ID=\"$logsource_id{$device_id}->[0]\", \t";
		print "Log source name=\"$logsource_id{$device_id}->[1]\", \t";
		print "Log source device type ID=\"$logsource_id{$device_id}->[2]\", \t";
		print "Log source device type name=\"$logsource_id{$device_id}->[3]\", \t";
		print "Log source device type description=\"$logsource_id{$device_id}->[4]\", \n";
	} # End of 'if $debug'

}
close(LOG_SOURCE_MAPPINGS);

	open(LOG_SOURCE_MAPPINGS, '<', $log_source_mappings) or die "\nCan't connect to QRadar Postgresql database, nor is $log_source_mappings available in the current folder, exiting for lack of device table input\n\n";
	while (<LOG_SOURCE_MAPPINGS>) {
		($log_source_id, $log_source_name, $log_source_device_type_id, $log_source_device_type_name, $log_source_device_type_description) = split(/,/);
	
		# Here we test if we can read a copy of the unified hash array from the saved file
		if ($debug) {
			print "log source id is: $log_source_id\n";
			print "log source name is: $log_source_name\n";	
			print "log source device type id is: $log_source_device_type_id\n";	
			print "log source device type name is: $log_source_device_type_name\n";	
			print "log source device type description is: $log_source_device_type_description\n";	
		} # end of if ($debug)
 	} # end of while (<LOG_SOURCE_MAPPINGS>)

# Done processing log source mappings
#

# On to qid mappings
#  Less error checking and debug options for this file as there are no complex unification of hash arrays
#

# 
open(QID_MAPPINGS, '>', $qid_mappings) or die $!;

# Load up a hash array of qid mappings from the postgresql qidmap table
#
#
my $stmt = qq(SELECT qid, qname, qdescription from qidmap;);
my $sth = $dbHand->prepare( $stmt );
my $rv = $sth->execute() or die $DBI::errstr;
if($rv < 0) {
   print $DBI::errstr;
}


while(my @row = $sth->fetchrow_array()) {

        $qid = $row[0];
        $qname = $row[1];
        $qdescription = $row[2];

	print QID_MAPPINGS "$qid,$qname,$qdescription\n";

}
close(QID_MAPPINGS);



# Close the database, turn off the lights
#
#
$dbHand->disconnect();

exit;

# coding reference below here

# 67,Asset Profiler-2 :: qr-con-vm,267,AssetProfiler,Asset Profiler
# 63,Custom Rule Engine-8 :: qr-con-vm,18,EventCRE,Custom Rule Engine
# 71,PaSeries @ 10.164.0.159,206,PaSeries,Palo Alto PA Series

#Log source ID="67",     Log source name="Asset Profiler-2 :: qr-con-vm",        Log source device type ID="267",        Log source device type name="AssetProfiler",    Log source device type description="Asset Profiler",
#Log source ID="63",     Log source name="Custom Rule Engine-8 :: qr-con-vm",    Log source device type ID="18",         Log source device type name="EventCRE",         Log source device type description="Custom Rule Engine",
#Log source ID="71",     Log source name="PaSeries @ 10.164.0.159",      Log source device type ID="206",        Log source device type name="PaSeries",         Log source device type description="Palo Alto PA Series",

