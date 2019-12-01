#!/usr/bin/perl
# (C) 2019 Pali

use 5.010;
use strict;
use warnings;

use Net::DBus qw(:typing);
use Net::DBus::Error;
use Net::DBus::Reactor;
use Net::DBus::RemoteService;
use Net::DBus::Service;

$| = 1;
$SIG{PIPE} = 'IGNORE';

my %sockets;

my $reactor = Net::DBus::Reactor->main();
my $bus = Net::DBus->system();
my $bus_object = $bus->get_bus_object();
main::Agent->new(main::Application->new(main::Service->new($bus), '/org/hsphfpd/application'), '/telephony/client_agent');
my $hsphfpd_service = Net::DBus::RemoteService->new($bus, '', 'org.hsphfpd');
my $hsphfpd_manager = $hsphfpd_service->get_object('/', 'org.hsphfpd.ApplicationManager');
$bus_object->connect_to_signal('NameOwnerChanged', \&bus_name_owner_changed);
bus_name_owner_changed('org.hsphfpd', '', 'org.hsphfpd');
$reactor->run();
exit 0;

sub bus_name_owner_changed {
	my ($name, $old, $new) = @_;
	return unless $name eq 'org.hsphfpd';
	if ($old ne '') {
		shutdown $_, 2 foreach values %sockets;
		%sockets = ();
	}
	if ($new ne '') {
		eval { $hsphfpd_manager->RegisterApplication(dbus_object_path('/org/hsphfpd/application')); 1 } or print "Registering application failed: $@";
	}
}


package main::Service;
use parent 'Net::DBus::Service';
sub new { bless { bus => $_[1], service_name => $_[1]->get_unique_name(), objects => {} }, $_[0] }


package main::Application;
use parent 'Net::DBus::Object';
use Net::DBus::Exporter 'org.freedesktop.DBus.ObjectManager';
BEGIN {
	dbus_method('GetManagedObjects', [], [ [ 'dict', 'objectpath', [ 'dict', 'string', [ 'dict', 'string', [ 'variant' ] ] ] ] ], { strict_exceptions => 1, return_names => [ 'object_paths_interfaces_and_properties' ] });
	dbus_signal('InterfacesAdded', [ 'objectpath', [ 'dict', 'string', [ 'dict', 'string', [ 'variant' ] ] ] ], { param_names => [ 'object_path', 'interfaces_and_properties' ] });
	dbus_signal('InterfacesRemoved', [ 'objectpath', [ 'array', 'string' ] ], { param_names => [ 'object_path', 'interfaces' ] });
}
sub GetManagedObjects { { '/org/hsphfpd/application/telephony/client_agent' => { 'org.hsphfpd.TelephonyAgent' => { Role => 'client' } } } }


package main::Agent;
use parent 'Net::DBus::Object';
use Net::DBus::Exporter 'org.hsphfpd.TelephonyAgent';
BEGIN {
	dbus_method('NewConnection', [ 'caller', 'objectpath', 'unixfd', [ 'dict', 'string', [ 'variant' ] ] ], [], { strict_exceptions => 1, param_names => [ 'endpoint', 'socket', 'properties' ] });
	dbus_property('Role', 'string', 'read', { strict_exceptions => 1 });
}
sub Role { 'client' }
sub NewConnection {
	my ($self, $caller, $path, $fd, $properties) = @_;
	die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Canceled', message => qq(Cannot open supplied file descriptor "$fd": Bad file descriptor)) unless $fd =~ /^[0-9]+$/;
	# After successful open() call, $socket owns $fd and close($socket) would close also $fd
	open my $socket, '+<&=', $fd or die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Canceled', message => qq(Cannot open supplied file descriptor "$fd": $!));
	select((select($socket), $| = 1)[0]); # enable autoflush
	die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Rejected', message => qq(Caller "$caller" does not own "org.hsphfpd" service)) if ($bus->get_service_owner('org.hsphfpd') // '') ne $caller;
	die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Rejected', message => qq(Invalid object path)) unless defined $path and $path =~ m{^/};
	die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Rejected', message => qq(Invalid properties structure)) unless ref $properties eq 'HASH';
	my $indicators = $properties->{Indicators};
	my $indicators_reporting;
	my $call_waiting_notifications;
	my $voice_recognition;
	my $response_and_hold_state = -1;
	my $voice_call_state = 0; # 0 = no, 1 = ringing incoming, 2 = active incoming, 3 = hold incoming, 4 = rining outgoing, 5 = active outing, 6 = hold outgoing
	my %indicator_num; # name => num; name: service, call, callsetup, call_setup, callheld, signal, roam
	my %indicator_state;
	my %indicator_value = (service => 1, call => 0, callsetup => 0, call_setup => 0, callheld => 0, signal => 5, roam => 0);
	die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Rejected', message => qq(Invalid Indicators structure)) unless defined $indicators and ref $indicators eq 'ARRAY';
	for (0..$#{$indicators}) {
		die Net::DBus::Error->new(name => 'org.hsphfpd.Error.Rejected', message => qq(Invalid Indicators structure)) unless defined $indicators->[$_] and ref $indicators->[$_] eq '';
		$indicator_num{$indicators->[$_]} = $_+1;
		$indicator_state{$_} = 1 if exists $indicator_value{$_};
	}
	print "New telephony connection: caller=$caller path=$path fd=$fd indicators=(" . (join ',', @{$indicators}) . ")\n";
	my $close_connection = sub {
		print "Closing connection: path=$path\n";
		$reactor->remove_read(fileno $socket);
		$reactor->remove_exception(fileno $socket);
		shutdown $socket, 2;
		delete $sockets{$socket};
		close $socket;
	};
	my $socket_write = sub {
		my ($line) = @_;
		print "$path write: $line\n";
		my $success = eval { print $socket "\r\n$line\r\n" };
		if (not $success) {
			my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
			print "Writing data to socket failed: $error";
			$close_connection->();
		}
		return $success;
	};
	$reactor->add_read(fileno $socket, sub {
		while (1) {
			my $line = eval { local $/ = "\r"; <$socket> };
			if (not defined $line) {
				last if $!{EAGAIN};
				my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
				print "Reading data from socket failed: $error";
				return $close_connection->();
			}
			$line =~ s/^\s*//;
			$line =~ s/\s*$//;
			next unless length $line;
			print "$path read: $line\n";
			if ($line =~ /^AT\+CMER=3,\s*0,\s*0,\s*(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'activating' : 'deactivating') . " reporting of AG indicators\n";
				$indicators_reporting = $enable;
				$socket_write->('OK') or return;
				if ($indicators_reporting) {
					foreach (@{$indicators}) {
						if ($indicator_state{$_}) {
							$socket_write->("+CIEV: $indicator_num{$_},$indicator_value{$_}") or return;
						}
					}
				}
			} elsif ($line =~ /^AT\+CCWA=(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of call waiting notifications\n";
				$call_waiting_notifications = $enable;
				$socket_write->('OK') or return;
			} elsif ($line =~ /^AT\+BIA=((?:0|1|)(?:,\s*(?1))?)$/) {
				my @inds = split /,\s*/, $1;
				print "Request for activating or deactivating individual indicators\n";
				my $error;
				my @enabled;
				for my $ind (0..$#inds) {
					if ($ind > $#{$indicators}) {
						print 'Indicator with id ' . ($ind+1) . " does not exist\n";
						$error = 1;
					} elsif (not exists $indicator_value{$indicators->[$ind]}) {
						print "Indicator $indicators->[$ind] is not supported\n" if $inds[$ind] eq '1';
					} elsif ($inds[$ind] eq '1' and not $indicator_state{$indicators->[$ind]}) {
						print "Activating indicator $indicators->[$ind]\n";
						$indicator_state{$indicators->[$ind]} = 1;
						push @enabled, $indicators->[$ind];
					} elsif ($inds[$ind] eq '0' and $indicator_state{$indicators->[$ind]}) {
						print "Deactivating AG indicator $indicators->[$ind]\n";
						$indicator_state{$indicators->[$ind]} = 0;
					}
				}
				$socket_write->($error ? 'ERROR' : 'OK') or return;
				if ($indicators_reporting) {
					foreach (@enabled) {
						if ($indicator_state{$_}) {
							$socket_write->("+CIEV: $indicator_num{$_},$indicator_value{$_}") or return;
						}
					}
				}
			} elsif ($line eq 'AT+BINP=1') {
				print "Request for phone number corresponding to the last voice tag\n";
				$socket_write->('+BINP: "+123456789"') or return;
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+BLDN') {
				print "Request for calling last number\n";
				$socket_write->('OK') or return;
				if ($voice_recognition) {
					$voice_recognition = 0;
					$socket_write->('+BVRA: 0') or return;
				}
				# Outgoing call set-up successfully initiated
				$indicator_value{callsetup} = $indicator_value{call_setup} = 2;
				$socket_write->("+CIEV: $indicator_num{callsetup},$indicator_value{callsetup}") or return;
				$socket_write->("+CIEV: $indicator_num{call_setup},$indicator_value{call_setup}") or return;
				$indicator_value{callsetup} = $indicator_value{call_setup} = 3;
				# Remote party reached and being alerted
				$socket_write->("+CIEV: $indicator_num{callsetup},$indicator_value{callsetup}") or return;
				$socket_write->("+CIEV: $indicator_num{call_setup},$indicator_value{call_setup}") or return;
				# Remote party answered
				$indicator_value{call} = 1;
				$socket_write->("+CIEV: $indicator_num{call},$indicator_value{call}") or return;
				# Call active
				$indicator_value{callsetup} = $indicator_value{call_setup} = 0;
				$socket_write->("+CIEV: $indicator_num{callsetup},$indicator_value{callsetup}") or return;
				$socket_write->("+CIEV: $indicator_num{call_setup},$indicator_value{call_setup}") or return;
				$voice_call_state = 5;
			} elsif ($line =~ /^AT\+BVRA=([0-1])$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of voice recognition function\n";
				$voice_recognition = $enable;
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+NREC=0') {
				print "Request for disabling of noise reduction and echo canceling\n";
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+BTRH?') {
				print "Request for state of Response and Hold feature\n";
				if ($response_and_hold_state != -1) {
					$socket_write->("+BTRH: $response_and_hold_state") or return;
				}
				$socket_write->('OK') or return;
			} elsif ($line =~ /^AT\+BTRH=([0-2])$/) {
				my $new_state = $1;
				print 'Request for chaning state of Response and Hold feature to ' . ($new_state == 0 ? 'put incoming call on hold' : $new_state == 1 ? 'accept incoming held call' : 'reject incoming held call') . "\n";
				# ERROR means that there is no held call
				$socket_write->('ERROR') or return;
#				$response_and_hold_state = $new_state;
			} elsif ($line =~ /^AT\+CSRGETSMS=([0-9]+)$/) {
				my $index = $1;
				print "Request for content of SMS with index $index\n";
				$socket_write->("+CSRSMS: This is SMS with index $index") or return;
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+APLSIRI?') {
				print "Request for Siri status\n";
				# 2 = Siri is available but not enabled
				$socket_write->('+APLSIRI: 2') or return;
			} elsif ($line =~ /^AT\+APLEFM=(0x[0-9a-fA-F]+|[0-9]+)$/) {
				print "Siri Eyes Free mode changed";
				# OK is the only allowed response
				$socket_write->('OK') or return;
			} elsif ($line eq 'ATA') {
				print "Request for accepting incoming call\n";
				$socket_write->('OK') or return;
				if ($voice_recognition) {
					$voice_recognition = 0;
					$socket_write->('+BVRA: 0') or return;
				}
				$indicator_value{call} = 1;
				$indicator_value{callsetup} = $indicator_value{call_setup} = 0;
				foreach (qw(call callsetup call_setup)) {
					if ($indicator_state{$_}) {
						$socket_write->("+CIEV: $indicator_num{$_},$indicator_value{$_}") or return;
					}
				}
			} elsif ($line eq 'AT+CHUP') {
				print "Request for terminating active or rejecting incoming call\n";
				$socket_write->('OK') or return;
				$indicator_value{call} = 0;
				$indicator_value{callsetup} = $indicator_value{call_setup} = 0;
				foreach (qw(call callsetup call_setup)) {
					if ($indicator_state{$_}) {
						$socket_write->("+CIEV: $indicator_num{$_},$indicator_value{$_}") or return;
					}
				}
				$voice_call_state = 0;
			} elsif ($line =~ /AT\+CHLD=([0-4])([0-9]+)?$/) {
				print "Call hold or multiparty handling request\n";
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+COPS=3,0') {
				print "Request for setting format for operator name to string\n";
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+COPS?') {
				print "Request for operator name\n";
				$socket_write->('+COPS: 0,0,"Operator Name"') or return;
				$socket_write->('OK') or return;
			} elsif ($line =~ /^AT\+CMEE=(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of Extended Audio Gateway Error Result Code\n";
				$socket_write->('OK') or return;
			} elsif ($line =~ /^AT\+CLIP=(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of Calling Line Identification notification\n";
				$socket_write->('OK') or return;
			} elsif ($line =~ /^AT\+VTS=([0-9#*A-D])$/) {
				my $dtmf = $1;
				print "Request for sending DTMF code $dtmf\n";
				$socket_write->('OK') or return;
			} elsif ($line eq 'AT+CNUM') {
				print "Request for Subscriber Number Information\n";
				$socket_write->('+CNUM: ,"+123456789",128,,4') or return;
				$socket_write->('OK') or return;
			} elsif ($line eq 'ERROR') {
				print "Received ERROR\n";
				# Some devices send invalid ERROR command in HF role. Do not send anything as it just generates another ERROR
			} else {
				print "Received Unknown command\n";
				$socket_write->('ERROR') or return;
			}
		}
	});
	$reactor->add_exception(fileno $socket, $close_connection);
	$sockets{$socket} = $socket;
}
