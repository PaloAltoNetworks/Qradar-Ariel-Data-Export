#!/usr/bin/perl

# Copyright 2025 Palo Alto Networks, Inc.
# Released under Apache 2.0 license
# Paul Vinson - dl-qradar-data-export@paloaltonetworks.com
#
# Release 1.0

# Two methods to use this script;
# 1) Send lines of ariel dump records into this script as stdin:  "cat <Ariel dump file> | ./process_arielClientdump.pl"
# 2) Use script 'ariel_dump.sh' to perform massive parallelization of input to multiple instances fo this script.
#    See documentation for details

#
# Designate the place to read the input file that contains the log source / log source mappings
# The below two examples will either let you set an absolute path, or look for it in the current directory
$log_source_mappings = "${ARGV[0]}/log_source_mappings.out";

#
# Designate the place to read the input file that contains the qid mappings
# The below two examples will either let you set an absolute path, or look for it in the current directory
$qid_mappings = "${ARGV[0]}/qid_mappings.out";

#
# Designate the place to store the processed files, stored under this folder in
# $processed_output/<YYYY>/<MM>/<DD>/qradar-<YYYY>-<MM>-<DD>-<Log Source Type Name>.json
$processed_output_tld = "${ARGV[1]}";

# No user tunable parameters below this line
#
#
###################################################################
#
# This is handy if you want to get a dump of one record to see what the fields look like.   Simply uncomment the debug setting
#  here and it will automatically exit after printing out all the fields in the "print debug" section far below
# Note:  When you want to use it this way, capture a single Ariel Dump record and pipe it into this script.  Don't run the ariel_dump.sh script as
#  this process won't make it through the parallelization routines.
# Also, don't forget to comment out debug=true when finished or things won't work with the ariel_dump.sh script.
# Finally, you have to change the $ARGV[x] variables used above for the mappings files to actually point to a file
#
#$debug = true;


use lib('/opt/qradar/lib/perl');
use lib('/opt/qradar/bin/ca_jail/lib64/perl5/vendor_perl');

use Encode;
use Data::Dumper;
use JSON::XS;
use POSIX qw(strftime);
use File::Path qw(make_path remove_tree);
use IO::Compress::Gzip qw(gzip $GzipError);

$Data::Dumper::Terse = 1;

#$| = 1; # turn on autoflush

# Let's load up log source mappings and get them loaded up into an hash of arrays
#
open(LOG_SOURCE_MAPPINGS, '<', $log_source_mappings) or die "\n\tCan't open log_source_mappings.  Did you forget to modify the variables at the top of this script?\n\n";
	
        while (<LOG_SOURCE_MAPPINGS>) {
                ($load_log_source_id, $load_log_source_name, $load_log_source_device_type_id, $load_log_source_device_type_name, $load_log_source_device_type_description) = split(/,/);


                # Cycle through the lines in the log source mappings file and load up a hash of arrays
                $logsource_id{$load_log_source_id}->[0] = "$load_log_source_id";                        # Log source ID
                $logsource_id{$load_log_source_id}->[1] = "$load_log_source_name";                      # Log source name
                $logsource_id{$load_log_source_id}->[2] = "$load_log_source_device_type_id";            # Log source devicetype ID
                $logsource_id{$load_log_source_id}->[3] = "$load_log_source_device_type_name";          # Log source devicetype name
                $logsource_id{$load_log_source_id}->[4] = "$load_log_source_device_type_description";   # Log source devicetype description

                chomp($logsource_id{$load_log_source_id}->[4]);

                if ($debug) {
                        print "Log source ID=\"$logsource_id{$load_log_source_id}->[0]\", \t";
                        print "Log source name=\"$logsource_id{$load_log_source_id}->[1]\", \t";
                        print "Log source device type ID=\"$logsource_id{$load_log_source_id}->[2]\", \t";
                        print "Log source device type name=\"$logsource_id{$load_log_source_id}->[3]\", \t";
                        print "Log source device type description=\"$logsource_id{$load_log_source_id}->[4]\"\n";
                        } # End of 'if $debug'

        } # end of while (<LOG_SOURCE_MAPPINGS>)

close(LOG_SOURCE_MAPPINGS);

# Done with loading up log source mappings, on to qid mappings

# By default we're not going to load up these mappings unless needed in the JSON $ariel_record, due to the size (720k entries) of QID mappings.
#  It is recognized, however, that significant time has been invested by QRadar customers and they may want to leverage their investment in custom QID mappings upon export of data.
#  If you need some of these enabled, you can uncomment the next lines and then see below where you can include them in $ariel_record if desired.
#
#open(QID_MAPPINGS, '<', $qid_mappings) or die "\n\tCan't open qid_mappings.  Did you forget to modify the variables at the top of this script?\n\n";
#
#	while (<QID_MAPPINGS>) {
#		($qid_mapping_id, $qname, $qdescription) = split(/,/);
#
#		# Cycle through the lines in the qid mappings file and load up a hash of arrays
#		$qid_hash{$qid_mapping_id}->[0] = $qid_mapping_id;	# QID
#		$qid_hash{$qid_mapping_id}->[1] = $qname;		# QID Name
#		$qid_hash{$qid_mapping_id}->[2] = $qdescription;	# QID Description
#
#		if ($debug) {
#			sleep(5);
#			print "\n\n";
#			print "QID=\"$qid_hash{$qid_mapping_id}->[0]\", \t";
#			print "QID Name=\"$qid_hash{$qid_mapping_id}->[1]\", \t";
#			print "QID Description=\"$qid_hash{$qid_mapping_id}->[2]\", \t";
#			exit;
#			} # End of 'if $debug'
#	} # End of while (<QID_MAPPINGS>) {


# Ok, here is where things get serious.   We're going to loop city to process whatever STDIN gives us.   Lotsa time spent developing this section
#
#
while (<STDIN>) {

	# And here we parsing the entire record put out by the Ariel Client Dump java program.   We parse every field just in case.
	#  This is undoubtedly a slow regex parse, but we heavily parallelize this process to make it palatable.

	/^com.q1labs.core.types.event.NormalizedEvent@(?<qradar_normalized_event_id>.*?)\[destinationPorts=(?<destination_ports>.*?),deviceEventId=(?<device_event_id>.*?),deviceId=(?<device_id>.*?),deviceTime=(?<device_time_epoch_milliseconds>.*?),dstMACAddress=(?<destination_mac_address>.*?),dstPostNATIPAddress=(?<destination_post_nat_ip_address>.*?),dstPostNATPort=(?<destination_post_nat_port>.*?),dstPreNATIPAddress=(?<destination_pre_nat_ip_address>.*?),dstPreNATPort=(?<destination_pre_nat_port>.*?),eventCollectorID=(?<event_collector_id>.*?),identityChangeEvent=(?<identity_change_event>.*?),logSourceIdentifier=(?<log_source_identifier>.*?),obfuscationNormalizedEventProperties=(?<obfuscation_normalized_event_properties>.*?),obfuscationProperties=(?<obfuscation_properties>.*?),payload=\{(?<encoded_payload>.*?)\},pcapID=(?<pcap_id>.*?),protocolConfigId=(?<protocol_config_id>.*?),qidDeviceTypeId=(?<qid_device_type_id>.*?),qidEventCategory=(?<qid_event_category>.*?),qidEventId=(?<qid_event_id>.*?),sourcePorts=(?<source_ports>.*?),srcMACAddress=(?<source_mac_address>.*?),srcPostNATIPAddress=(?<source_post_nat_ip_address>.*?),srcPostNATPort=(?<source_post_nat_port>.*?),srcPreNATIPAddress=(?<source_pre_nat_ip_address>.*?),srcPreNATPort=(?<source_pre_nat_port>.*?),annotations=(?<annotations>.*?),aqlCustomProperties=(?<aql_custom_properties>.*?),cachedResults=(?<cached_results>.*?),calculatedProperties=(?<calculated_properties>.*?),category=(?<category>.*?),credibility=(?<credibility>.*?),customProperties=(?<custom_properties>.*?),customPropertiesLock=(?<custom_properties_lock>.*?),customRuleList=(?<custom_rule_list>.*?),customRuleResultArray=(?<custom_rule_result_array>.*?),destination=(?<destination>.*?),destinationPort=(?<destination_port>.*?),destinationV6=(?<destination_v6>.*?),domainID=(?<domain_id>.*?),duration=(?<duration>.*?),epStorageTimeMap=(?<ep_storage_time_map>.*?),eventAnnotations=(?<event_annotations>.*?),eventCount=(?<event_count>.*?),eventOffenseAnnotations=(?<event_offense_annotations>.*?),eventProcessorId=(?<event_processor_id>.*?),gccSet=(?<gcc_set>.*?),historicalCorrelationId=(?<historical_correlation_id>.*?),intervalId=(?<intervalid>.*?),offenseStartTime=(?<offense_start_time>.*?),persistentProperties=(?<persistent_properties>.*?),protocol=(?<protocol>.*?),qid=(?<qid>.*?),relevance=(?<relevance>.*?),severity=(?<severity>.*?),source=(?<source>.*?),sourcePort=(?<source_port>.*?),sourceV6=(?<source_v6>.*?),startTime=(?<epoch_start_time>.*?),taggedFields=(?<tagged_fields>.*?),token=(?<token>.*?),userName=(?<user_name>.*?),bitmask=(?<bitmask>.*?)\]$/;


	# Let's first decode the payload and store into it's own variable
	#  This is a necessary step as the encoded payload is only useful for potentially repudiation purposes
	#
	my @chars = map { chr } split /,/, $+{encoded_payload};
	$decoded_payload = encode('UTF-8', join('', @chars));
	chomp($decoded_payload);

	# Do some time conversion.  We're going to drop the milliseconds off for easier processing
	$converted_epoch_time = strftime("%Y-%m-%d %H:%M:%S", gmtime($+{device_time_epoch_milliseconds}/1000));

	# In order for the loading of the JSON record to work, we have to load the name of the named capture group to a regular variable
	#  Seems like one cannot dereference hash values with a key derived from a named capture group
	#
	$device_id = "$+{device_id}";

	# Load up the JSON record we are going to dump
	#  See the next section for possible additions to this record.   I made a best guess as useful things to include
	my $ariel_record = {
		destination_ip => "$+{destination}",
		destination_port => "$+{destination_port}",
		event_device_gmt_time => "$converted_epoch_time",
		event_payload => "$decoded_payload",
		log_source_device_type_descripton => "$logsource_id{$device_id}->[4]",
		log_source_device_type_name => "$logsource_id{$device_id}->[3]",
		log_source_identifier => "$+{log_source_identifier}",
		log_source_name => "$logsource_id{$device_id}->[1]",
		qradar_event_category => "$+{qid_event_category}",
		qradar_event_id => "$+{qid}",
		source_ip => "$+{source}",
		source_port => "$+{source_port}",
		user_name => "$+{user_name}",
	}; # End of my $ariel_record

		# The below is here to make it easy to populate the $ariel_record above to add more JSON fields if desired
		#  All of these are automatically parsed and available for every exported Ariel record
		#
		# Note: no need to attempt to sort them in the $ariel_record above, as things that read JSON do not care
		#
                # annotations => "$+{annotations}",
                # aql_custom_properties => "$+{aql_custom_properties}",
                # bitmask => "$+{bitmask}",
                # cached_results => "$+{cached_results}",
                # calculated_properties => "$+{calculated_properties}",
                # category => "$+{category}",
                # category => "$+{category}",
                # credibility => "$+{credibility}",
                # custom_properties => "$+{custom_properties}",
                # custom_properties_lock => "$+{custom_properties_lock}",
                # custom_rule_list => "$+{custom_rule_list}",
                # custom_rule_result_array $+{custom_rule_result_array}",
                # decoded_payload => "$decoded_payload",
                # destination => "$+{destination}",
                # destination_mac_address => "$+{destination_mac_address}",
                # destination_port => "$+{destination_port}",
                # destination_ports => "$+{destinationPorts}",
                # destination_post_nat_ip_address => "$+{destination_post_nat_ip_address}",
                # destination_post_nat_port => "$+{destination_post_nat_port}",
                # destination_pre_nat_ip_address => "$+{destination_pre_nat_ip_address}",
                # destination_pre_nat_port => "$+{destination_pre_nat_port}",
                # destination_v6 => "$+{destination_v6}",
                # device_event_id => "$+{device_event_id}",
                # device_id => "$+{device_id}",
                # device_time_epoch_milliseconds => "$+{device_time_epoch_milliseconds}",
                # domain_id => "$+{domain_id}",
                # duration => "$+{duration}",
                # encoded_payload => "$+{encoded_payload}",
                # epoch_start_time => "$+{epoch_start_time}",
                # ep_storage_time_map => "$+{ep_storage_time_map}",
                # event_annotations => "$+{event_annotations}",
                # event_collector_id => "$+{event_collector_id}",
                # event_count => "$+{event_count}",
                # event_device_time_epoch_milliseconds => "$+{device_time_epoch_milliseconds}",
                # event_device_time_iso_8601 => scalar localtime($+{device_time_epoch_milliseconds}),
                # event_offense_annotations => "$+{event_offense_annotations}",
                # event_processor_id => "$+{event_processor_id}",
                # gcc_set => "$+{gcc_set}",
                # historical_correlation_id => "$+{historical_correlation_id}",
                # identity_change_event => "$+{identity_change_event}",
                # intervalid => "$+{intervalid}",
                # log_source_device_type_id => "$logsource_id{$device_id}->[2]",
                # log_source_id => "$+{device_id}",
                # log_source_identifier => "$+{log_source_identifier}",
                # obfuscation_normalized_event_properties => "$+{obfuscation_normalized_event_properties}",
                # obfuscation_properties => "$+{obfuscation_properties}",
                # offense_start_time => "$+{offense_start_time}",
                # pcap_id => "$+{pcap_id}",
                # persistent_properties => "$+{persistent_properties}",
                # protocol_config_id => "$+{protocol_config_id}",
                # protocol => "$+{protocol}",
                # qid_device_type_id => "$+{qid_device_type_id}",
                # qid_event_category => "$+{qid_event_category}",
                # qid_event_id => "$+{qid_event_id}",
                # qid => "$+{qid}",
                # qradar_event_id_description => "$qid_hash{$+{qid}}->[2]",
                # qradar_event_id_name => "$qid_hash{$+{qid}}->[1]",
                # qradar_event_id => "$+{qid}",
                # qradar_normalized_event_id => "$+{qradar_normalized_event_id}",
                # relevance => "$+{relevance}",
                # severity => "$+{severity}",
                # source_mac_address  => "$+{source_mac_address}",
                # source_port => "$+{source_port}",
                # source_ports => "$+{source_ports}",
                # source_post_nat_ip_address => "$+{source_post_nat_ip_address}",
                # source_post_nat_port => "$+{source_post_nat_port}",
                # source_pre_nat_ip_address => "$+{source_pre_nat_ip_address}",
                # source_pre_nat_port => "$+{source_pre_nat_port}",
                # source => "$+{source}",
                # source_v6 => "$+{source_v6}",
                # tagged_fields => "$+{tagged_fields}",
                # token => "$+{token}",
                # user_name => "$+{user_name}",

		# These two are only available if you (far) above uncomment the lines to load up the qid_mappings file
		#  which should be provided and put in the BASEDIR folder
		#
		# Here is QID Name:
		# qid_name => "$qid_hash{$qid_mapping_id}->[1]",
		# Here is QID Description:
		# qid_description => "$qid_hash{$qid_mapping_id}->[2]",



	$output_dir_string = strftime "%Y/%m/%d", gmtime(($+{device_time_epoch_milliseconds}/1000));

	# use this for per day by logsource type
	$filename_string = strftime "%Y-%m-%d-qradar-ep$+{event_processor_id}-$logsource_id{${device_id}}->[3]", gmtime(($+{device_time_epoch_milliseconds}/1000));
	#
	# use this for per day & per hour by logsource type
	#$filename_string = strftime "%Y-%m-%d-%H-qradar-ep$+{event_processor_id}-$logsource_id{${device_id}}->[3]", gmtime(($+{device_time_epoch_milliseconds}/1000));

	$fh_ucase_fqn_filename_string = uc("$filename_string");
	make_path("$processed_output_tld/$output_dir_string", { chmod => 0755, });

	# This line will compress the output files with perl's builtin gzip module
	#
	my $fh_ucase_fqn_filename_string = IO::Compress::Gzip->new("$processed_output_tld/$output_dir_string/$filename_string.json.gz", Minimal => 1, AutoClose => 1, Append => 1) or die "Cannot open file: $GzipError\n";

	# Toggle this one instead to output uncompressed
	#
	#open($fh_ucase_fqn_filename_string, '>>', "$processed_output_tld/$output_dir_string/$filename_string.json") or die;

 
	# Dump the JSON Record
	my $ariel_record_json = encode_json $ariel_record;
	print $fh_ucase_fqn_filename_string Dumper($ariel_record_json) or die;

# This is handy if you want to get a dump of one record to see what the fields look like.   Simply uncomment the debug setting
#  at the top of this script and it will automatically exit after printing out all the below
# Note:  When you want to use it this way, capture a single Ariel Dump record and pipe it into this script.  Don't run the ariel_dump.sh script as
#  this process won't make it through the parallelization routines.
# Also, don't forget to comment out debug=true when finished or things won't work with the ariel_dump.sh script.
#
if ($debug) {
	print "qradar_normalized_event_id (Ariel: NormalizedEvent) is $+{qradar_normalized_event_id}\n";
	print "destination_ports (Ariel: destinationPorts) is $+{destinationPorts}\n";
	print "device_event_id (Ariel: deviceEventId) is $+{device_event_id}\n";
	print "device_id (Ariel: deviceId) is $+{device_id}\n";
	print "device_time_epoch_milliseconds (Ariel: deviceTime) is $+{device_time_epoch_milliseconds}\n";
	print "destination_mac_address (Ariel: dstMACAddress) is $+{destination_mac_address}\n";
	print "destination_post_nat_ip_address (Ariel: dstPostNATIPAddress) is $+{destination_post_nat_ip_address}\n";
	print "destination_post_nat_port (Ariel: dstPostNATPort) is $+{destination_post_nat_port}\n";
	print "destination_pre_nat_ip_address (Ariel: dstPreNATIPAddress) is $+{destination_pre_nat_ip_address}\n";
	print "destination_pre_nat_port (Ariel: dstPreNATPort) is $+{destination_pre_nat_port}\n";
	print "event_collector_id (Ariel: eventCollectorID) is $+{event_collector_id}\n";
	print "identity_change_event (Ariel: identityChangeEvent) is $+{identity_change_event}\n";
	print "log_source_identifier (Ariel: logSourceIdentifier) is $+{log_source_identifier}\n";
	print "obfuscation_normalized_event_properties (Ariel: obfuscationNormalizedEventProperties) is $+{obfuscation_normalized_event_properties}\n";
	print "obfuscation_properties (Ariel: obfuscationProperties) is $+{obfuscation_properties}\n";
	print "encoded_payload (Ariel: payload) is $+{encoded_payload}\n";
        print "decoded_payload is $decoded_payload\n";
        print "pcap_id (Ariel: pcapID) is $+{pcap_id}\n";
        print "protocol_config_id (Ariel: protocolConfigId) is $+{protocol_config_id}\n";
        print "qid_device_type_id (Ariel: qidDeviceTypeId) is $+{qid_device_type_id}\n";
        print "qid_event_category (Ariel: qidEventCategory) is $+{qid_event_category}\n";
        print "qid_event_id (Ariel: qidEventId) is $+{qid_event_id}\n";
        print "source_ports (Ariel: sourcePorts)is $+{source_ports}\n";
        print "source_mac_address (Ariel: srcMACAddress) is $+{source_mac_address}\n";
        print "source_post_nat_ip_address (Ariel: srcPostNATIPAddress)is $+{source_post_nat_ip_address}\n";
        print "source_post_nat_port (Ariel: srcPostNATPort) is $+{source_post_nat_port}\n";
        print "source_pre_nat_ip_address (Ariel: srcPreNATIPAddress) is $+{source_pre_nat_ip_address}\n";
        print "source_pre_nat_port (Ariel: srcPreNATPort) is $+{source_pre_nat_port}\n";
        print "annotations is (Ariel: annotations) $+{annotations}\n";
        print "aql_custom_properties (Ariel: aqlCustomProperties) is $+{aql_custom_properties}\n";
	print "cached_results (Ariel: cachedResults) is $+{cached_results}\n";
	print "calculated_properties (Ariel: calculatedProperties) is $+{calculated_properties}\n";
	print "category (Ariel: category) is $+{category}\n";
	print "credibility (Ariel: credibility) is $+{credibility}\n";
	print "custom_properties (Ariel: customProperties) is $+{custom_properties}\n";
	print "custom_properties_lock (Ariel: customPropertiesLock) is $+{custom_properties_lock}\n";
	print "custom_rule_list (Ariel: customRuleList) is $+{custom_rule_list}\n";
	print "custom_rule_result_array (Ariel: customRuleResultArray)is $+{custom_rule_result_array}\n";
	print "destination (Ariel: destination) is $+{destination}\n";
	print "destination_port (Ariel: destinationPort) is $+{destination_port}\n";
	print "destination_v6 (Ariel: destinationV6) is $+{destination_v6}\n";
	print "domain_id (Ariel: domainID) is $+{domain_id}\n";
	print "duration (Ariel: duration) is $+{duration}\n";
	print "ep_storage_time_map (Ariel: epStorageTimeMap) is $+{ep_storage_time_map}\n";
	print "event_annotations (Ariel: eventAnnotations) is $+{event_annotations}\n";
	print "event_count (Ariel: eventCount) is $+{event_count}\n";
	print "event_offense_annotations (Ariel: eventOffenseAnnotations) is $+{event_offense_annotations}\n";
	print "event_processor_id (Ariel: eventProcessorId) is $+{event_processor_id}\n";
	print "gcc_set (Ariel: gccSet) is $+{gcc_set}\n";
	print "historical_correlation_id (Ariel: historicalCorrelationId) is $+{historical_correlation_id}\n";
	print "intervalid (Ariel: intervalId) is $+{intervalid}\n";
	print "offense_start_time (Ariel: offenseStartTime) is $+{offense_start_time}\n";
	print "persistent_properties (Ariel: persistentProperties) is $+{persistent_properties}\n";
	print "protocol (Ariel: protocol) is $+{protocol}\n";
	print "qid (Ariel: qid) is $+{qid}\n";
	print "relevance (Ariel: relevance) is $+{relevance}\n";
	print "severity (Ariel: severity) is $+{severity}\n";
	print "source (Ariel: source) is $+{source}\n";
	print "source_port (Ariel: sourcePort) is $+{source_port}\n";
	print "source_v6 (Ariel: sourceV6) is $+{source_v6}\n";
	print "epoch_start_time (Ariel: startTime) is $+{epoch_start_time}\n";
	print "tagged_fields (Ariel: taggedFields) is $+{tagged_fields}\n";
	print "token (Ariel: token) is $+{token}\n";
	print "user_name (Ariel: userName) is $+{user_name}\n";
	print "bitmask (Ariel: bitmask) is $+{bitmask}\n";
	exit;
	} # end of "if ($debug)

} # end of 'while (<STDIN>)

for (glob "/proc/$$/fd/*") { POSIX::close($1) if m{/(\d+)$}; }

exit;

