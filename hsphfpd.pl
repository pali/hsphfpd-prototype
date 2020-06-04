#!/usr/bin/perl
# (C) 2019 Pali

use 5.010;
use strict;
use warnings;

# Replace socket() by poll() syscall and put POLLHUP events into exception fd set
# Needed to catch POLLHUP events in Net::DBus::Reactor's add_exception() method
use IO::Poll qw(POLLIN POLLOUT POLLERR POLLHUP);
BEGIN {
	*CORE::GLOBAL::select = sub {
		return CORE::select() if @_ == 0;
		return CORE::select($_[0]) if @_ == 1;
		my %masks = (0 => POLLIN, 1 => POLLOUT, 2 => POLLERR|POLLHUP);
		my @args;
		for (0..2) {
			next unless defined $_[$_];
			for my $fd (0..8*length $_[$_]) {
				push @args, $fd => $masks{$_} if vec $_[$_], $fd, 1;
			}
		}
		my $ret = IO::Poll::_poll((defined $_[3]) ? ($_[3] * 1000) : -1, @args);
		do { $_[$_] = "\x00" x length $_[$_] if defined $_[$_] } for 0..2;
		while ($ret >= 0 and @args) {
			my $fd = shift @args;
			my $mask = shift @args;
			do { vec($_[$_], $fd, 1) = 1 if $mask & $masks{$_} } for 0..2;
		}
		return $ret;
	};
}

use Net::DBus qw(:typing);
use Net::DBus::Error;
use Net::DBus::Reactor;
use Net::DBus::RemoteService;
use Net::DBus::Service;

BEGIN {
	require Net::DBus::Binding::Introspector;
	no warnings 'redefine';
	my $prev_to_xml = \&Net::DBus::Binding::Introspector::to_xml;
	*Net::DBus::Binding::Introspector::to_xml = sub {
		my $xml = $prev_to_xml->(@_);
		# Fix bug in to_xml(), node subname cannot start with "/"
		$xml =~ s{(.<node name=")/([^"])}{$1$2}g;
		return $xml;
	};
}

BEGIN {
	require Net::DBus::BaseObject;
	no warnings 'redefine';
	*Net::DBus::BaseObject::_get_sub_nodes = sub {
		my ($self) = @_;
		my %uniq;
		my $base = $self->{object_path};
		# Fix bug in _get_sub_nodes(), base cannot be "//"
		$base .= '/' if $base ne '/';
		foreach (keys %{$self->{children}}) {
			m/^$base([^\/]+)/;
			$uniq{$1} = 1;
		}
		return sort keys %uniq;
	};
	*Net::DBus::BaseObject::_dispatch_all_prop_read = sub {
		my ($self, $connection, $message) = @_;
		my $ins = $self->_introspector;
		if (!$ins) {
			return $connection->make_error_message($message,
				"org.freedesktop.DBus.Error.Failed",
				"no introspection data exported for properties"
			);
		}
		# Fix bug in _dispatch_all_prop_read, correct method name is "GetAll", not "Get"
		my ($pinterface) = $ins->decode($message, "methods", "GetAll", "params");
		my %values = ();
		foreach my $pname ($ins->list_properties($pinterface)) {
			unless ($ins->is_property_readable($pinterface, $pname)) {
				next; # skip write-only properties
			}
			$values{$pname} = eval {
				$self->_dispatch_property($pname);
			};
			if ($@) {
				return $connection->make_error_message($message,
					"org.freedesktop.DBus.Error.Failed",
					"error reading '$pname' in interface '$pinterface': $@"
				);
			}
		}
		my $reply = $connection->make_method_return_message($message);
		# Fix bug in _dispatch_all_prop_read, correct method name is "GetAll", not "Get"
		$self->_introspector->encode($reply, "methods", "GetAll", "returns", \%values);
		return $reply;
	};
}

BEGIN {
	require Net::DBus::Binding::Iterator;
	require Net::DBus::Binding::Message;
	no warnings 'redefine';
	my $prev_append = \&Net::DBus::Binding::Iterator::append;
	*Net::DBus::Binding::Iterator::append = sub {
		my ($self, $value, $type) = @_;
		# Fix bug in append, it does not support unixfd
		if (ref $value eq 'Net::DBus::Binding::Value' and $value->type() == &Net::DBus::Binding::Message::TYPE_UNIX_FD) {
			$self->append_unix_fd($value->value());
			return;
		}
		$prev_append->($self, $value, $type);
	};
}

BEGIN {
	require Net::DBus::Reactor;
	no warnings 'redefine';
	my $prev_dispatch_fd = \&Net::DBus::Reactor::_dispatch_fd;
	*Net::DBus::Reactor::_dispatch_fd = sub {
		my ($self, $type, $vec) = @_;
		# Fix bug in _dispatch_fd, exception type is marked incorrectly as error
		$type = 'exception' if $type eq 'error';
		return $prev_dispatch_fd->($self, $type, $vec);
	};
}

BEGIN {
	# Fix bug in dbus_unix_fd, it push TYPE_UNIX_FD into arrayref which is incorrect
	no warnings 'redefine';
	*Net::DBus::dbus_unix_fd = sub { Net::DBus::Binding::Value->new(&Net::DBus::Binding::Message::TYPE_UNIX_FD, $_[0]) };
	# Fix bug in Net::DBus, it does not export dbus_unix_fd, even when :typing is specified
	*dbus_unix_fd = \&Net::DBus::dbus_unix_fd;
}

$| = 1;
$SIG{PIPE} = 'IGNORE';

### Mapping tables ###

my %hf_features_mask;
{
	my @hf_features_defines = qw(echo-canceling-and-noise-reduction three-way-calling cli-presentation voice-recognition volume-control enhanced-call-status enhanced-call-control codec-negotiation hf-indicators esco-s4-settings enhanced-voice-recognition-status voice-recognition-text);
	my $tmp = 0b1;
	%hf_features_mask = map { (($tmp <<= 1) >> 1) => $_ } @hf_features_defines;
}

my %hf_profile_features_mask;
{
	my @hf_profile_features_defines = qw(echo-canceling-and-noise-reduction three-way-calling cli-presentation voice-recognition volume-control wide-band-speech enhanced-voice-recognition-status voice-recognition-text);
	my $tmp = 0b1;
	%hf_profile_features_mask = map { (($tmp <<= 1) >> 1) => $_ } @hf_profile_features_defines;
}

my %hf_codecs_map = (1 => 'CVSD', 2 => 'mSBC');
my %hf_indicators_map = (1 => 'enhanced-security', 2 => 'battery-level');
my $hf_indicator_battery = 2;

my %apple_features_mask;
{
	my @apple_features_defines = qw(apple-battery-level apple-dock-state apple-siri-status apple-noise-reduction-status);
	my $tmp = 0b10;
	%apple_features_mask = map { (($tmp <<= 1) >> 1) => $_ } @apple_features_defines;
}

my %ag_indicators;
my $ag_indicator_battchg;
my $ag_indicator_call;
my $ag_indicator_callsetup;
my $ag_indicator_call_setup;
{
	# Seems that Creative Labs headsets require at least "service" and "call" indicators, otherwise they drop HFP connection
	my @ag_indicators_defines = (
		# Indicators introduced in HF profile, version 0.6
		service => '0,1', call => '0,1',
		# Indicators introduced in HF profile, version 1.0
		callsetup => '0-3',
		# Indicators introduced in HF profile, version 1.5
		callheld => '0-2', signal => '0-5', roam => '0,1', battchg => '0-5',
		# Additional indicators defined in HF profile, version 1.00 Voting Draft
		call_setup => '0-3',
		# Additional indicators defined in ETS 300 916 - Edition 08
		sounder => '0,1', message => '0,1', vox => '0,1', smsfull => '0,1',
	);
	for (my $i = 0; $i < $#ag_indicators_defines; $i += 2) {
		$ag_indicators{$i/2+1} = { name => $ag_indicators_defines[$i], values => $ag_indicators_defines[$i+1] };
		$ag_indicator_battchg = $i/2+1 if $ag_indicators_defines[$i] eq 'battchg';
		$ag_indicator_call = $i/2+1 if $ag_indicators_defines[$i] eq 'call';
		$ag_indicator_callsetup = $i/2+1 if $ag_indicators_defines[$i] eq 'callsetup';
		$ag_indicator_call_setup = $i/2+1 if $ag_indicators_defines[$i] eq 'call_setup';
	}
}

my %ag_profile_features_mask;
{
	my @ag_profile_features_defines = qw(three-way-calling echo-canceling-and-noise-reduction voice-recognition in-band-ring-tone attach-voice-tag wide-band-speech);
	my $tmp = 0b1;
	%ag_profile_features_mask = map { (($tmp <<= 1) >> 1) => $_ } @ag_profile_features_defines;
}

### Global state ###

my $our_power_source = 'unknown';
my $our_battery_level = -1;

my $fd_num = 0;

# bluez adapter: /org/bluez/hciX
# bluez device: /org/bluez/hciX/dev_XX_XX_XX_XX_XX_XX
# hsphfpd endpoint: /org/hsphfpd/hciX/dev_XX_XX_XX_XX_XX_XX/XXX_XX
# hsphfpd audio transport: /org/hsphfpd/hciX/dev_XX_XX_XX_XX_XX_XX/audio_fdX
# hsphfpd profile path: /org/bluez/profile/XXX_XX
# hsphfpd profile: XXX_XX
# hsphfpd application: {service, path, manager, sig1, sig2, [agents], [audios], [telephonys]}
# hsphfpd audio agent: {type=audio, path, codec}
# hsphfpd telephony agent: {type=telephony, path, role}

my %profiles; # profile => exists
my %adapters; # adapter => {address, devices => {device => exists}, codecs => {air_codec => agent_codec => exists}}
my %devices; # device => {adapter, selected_profile, profiles => {profile => endpoint}}
my %endpoints; # endpoint => {device, audio, profile, object, properties, hs_volume_control, hfp_wide_band_speech, ag_features, ag_indicators, ag_indicators_reporting, ag_call_waiting_notifications, hf_features, csr_features, apple_features, hf_codecs, csr_codecs, selected_codec, socket, rx_volume_control, tx_volume_control, rx_volume_gain, tx_volume_gain}
my %audios; # audio => {endpoint, socket, object, mtu, air_codec, agent_codec, agent_path, application_service, application_path}
my @applications; # [application]

### Main code ###

my $reactor = Net::DBus::Reactor->main();

my $bus = Net::DBus->system();

my $bus_object = $bus->get_bus_object();
$bus_object->connect_to_signal('NameOwnerChanged', \&bus_name_owner_changed);

my $hsphfpd_service = $bus->export_service('org.hsphfpd');
my $hsphfpd_manager = main::Manager->new($hsphfpd_service, '/');
main::Profile->new($hsphfpd_manager, "org/bluez/profile/$_") foreach qw(hsp_ag hsp_hs hfp_ag hfp_hf);
main::PowerSupply->new($hsphfpd_manager, 'org/hsphfpd/power_supply');

my $bluez_service = Net::DBus::RemoteService->new($bus, ($bus->get_service_owner('org.bluez') // ''), 'org.bluez');
$bus->{services}->{'org.bluez'} = $bluez_service;
my $bluez_profile_manager = $bluez_service->get_object('/org/bluez', 'org.bluez.ProfileManager1');
my $bluez_object_manager = $bluez_service->get_object('/', 'org.freedesktop.DBus.ObjectManager');
$bluez_object_manager->connect_to_signal('InterfacesAdded', \&bluez_interfaces_added);
$bluez_object_manager->connect_to_signal('InterfacesRemoved', \&bluez_interfaces_removed);

my $sco_listening_socket;
print "Creating listening SCO socket\n";
# PF_BLUETOOTH => 31, SOCK_SEQPACKET => 5, BTPROTO_SCO => 2
socket $sco_listening_socket, 31, 5, 2 or print "Opening SCO listening socket failed: $!\n";
if ($sco_listening_socket) {
	# AF_BLUETOOTH => 31, struct sockaddr_sco { sa_family_t sco_family; bdaddr_t sco_bdaddr; }, sa_family_t = uint16_t, bdaddr_t = uint8_t[6] (in reverse order)
	bind $sco_listening_socket, pack 'S(H2)6', 31, reverse split /:/, "00:00:00:00:00:00" or do { print "Binding listening SCO socket to local address failed: $!\n"; close $sco_listening_socket; undef $sco_listening_socket; };
}
# SOL_BLUETOOTH => 274, BT_DEFER_SETUP => 7, int
my $kernel_defer_support = defined $sco_listening_socket && defined setsockopt $sco_listening_socket, 274, 7, pack 'i', 1;
# SOL_BLUETOOTH => 274, BT_VOICE => 11, struct bt_voice { uint16_t setting; }
my $kernel_msbc_support = $kernel_defer_support && defined getsockopt $sco_listening_socket, 274, 11;
# SOL_BLUETOOTH => 274, BT_VOICE_SETUP => 14, ...
my $kernel_anycodec_support = $kernel_defer_support && defined getsockopt $sco_listening_socket, 274, 14;
if ($sco_listening_socket) {
	if (listen $sco_listening_socket, 10) {
		$reactor->add_read(fileno $sco_listening_socket, sub { hsphfpd_accept_audio() });
	} else {
		print "Listening on SCO socket failed: $!\n";
		close $sco_listening_socket;
		undef $sco_listening_socket;
	}
}

bluez_enumerate_objects();

$SIG{INT} = $SIG{TERM} = sub {
	print "\nReceived signal, exiting...\n";
	exit 0 unless $reactor->{running};
	if (defined $sco_listening_socket) {
		print "Closing SCO listening socket\n";
		$reactor->remove_read(fileno $sco_listening_socket);
		close $sco_listening_socket;
		undef $sco_listening_socket;
	}
	hsphfpd_unregister_application_i($_) foreach reverse 0..$#applications;
	bluez_release_profiles();
	$reactor->shutdown();
};

$reactor->run();
exit 0;

### Subroutines ###

sub bus_name_owner_changed {
	my ($name, $old, $new) = @_;
	if ($name eq 'org.bluez') {
		if ($old ne '') {
			bluez_interfaces_removed($_, [ 'org.bluez.Adapter1' ]) foreach sort keys %adapters;
			bluez_interfaces_removed('/org/bluez', [ 'org.bluez.ProfileManager1' ]);
		}
		if ($new ne '') {
			$bluez_service->{owner_name} = $new;
			bluez_enumerate_objects();
		}
	}
	foreach (reverse 0..$#applications) {
		next unless $applications[$_]->{service} eq $name;
		hsphfpd_unregister_application_i($_);
	}
}

sub throw_dbus_error {
	my ($name, $message) = @_;
	print "Returning DBus error $name: $message\n";
	die Net::DBus::Error->new(name => $name, message => $message);
}


sub hsphfpd_register_application {
	my ($caller, $path) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid object path)) unless defined $path and $path =~ m{^/};
	throw_dbus_error('org.hsphfpd.Error.AlreadyExists', qq(Application "$caller" "$path" is already registered)) if grep { $_->{service} eq $caller and $_->{path} eq $path } @applications;
	print "Registering application $caller $path\n";
	my $application = { service => $caller, path => $path, agents => [], audios => [], telephonys => [] };
	my $timer_id; # postpone enumeration after register application callback finish
	$timer_id = $reactor->add_timeout(0, sub {
		if (not $application->{deleted}) {
			$application->{manager} = Net::DBus::RemoteService->new($bus, $caller, $caller)->get_object($path, 'org.freedesktop.DBus.ObjectManager');
			$application->{sigid1} = eval { $application->{manager}->connect_to_signal('InterfacesAdded', sub { hsphfpd_application_interfaces_added($application, @_) }) };
			if (not defined $application->{sigid1}) {
				print "Application $caller $path object manager returned error: $@";
			} else {
				$application->{sigid2} = eval { $application->{manager}->connect_to_signal('InterfacesRemoved', sub { hsphfpd_application_interfaces_removed($application, @_) }) };
				if (not defined $application->{sigid2}) {
					print "Application $caller $path object manager returned error: $@";
				} else {
					my $agents = eval { $application->{manager}->GetManagedObjects() };
					if (not defined $agents) {
						print "Application $caller $path object manager returned error: $@";
					} elsif (ref $agents ne 'HASH') {
						print "Application $caller $path object manager returned invalid response\n";
					} else {
						hsphfpd_application_interfaces_added($application, $_, $agents->{$_}) foreach sort keys %{$agents};
					}
				}
			}
		}
		$reactor->remove_timeout($timer_id);
	});
	push @applications, $application;
	return;
}

sub hsphfpd_unregister_application_i {
	my ($i) = @_;
	print "Unregistering application " . $applications[$i]->{service} . " " . $applications[$i]->{path} . " and all it's agents\n";
	if (exists $applications[$i]->{manager}) {
		eval { $applications[$i]->{manager}->disconnect_from_signal('InterfacesAdded', $applications[$i]->{sigid1}) };
		eval { $applications[$i]->{manager}->disconnect_from_signal('InterfacesRemoved', $applications[$i]->{sigid2}) };
		delete $applications[$i]->{manager};
	}
	my @audios = @{$applications[$i]->{audios}};
	hsphfpd_disconnect_audio($_) foreach @audios;
	my @telephonys = @{$applications[$i]->{telephonys}};
	hsphfpd_disconnect_telephony($_) foreach @telephonys;
	$applications[$i]->{deleted} = 1;
	splice @applications, $i, 1;
	if (@telephonys) {
		# if we disconnected some telephony connection then estalibsh a new via other telephony agent
		my $timer_id; # postpone connecting telephony agent after callback finish
		$timer_id = $reactor->add_timeout(0, sub {
			hsphfpd_connect_telephony($_) foreach sort keys %endpoints;
			$reactor->remove_timeout($timer_id);
		});
	}
	return;
}

sub hsphfpd_unregister_application {
	my ($caller, $path) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid object path)) unless defined $path and $path =~ m{^/};
	foreach (0..$#applications) {
		next unless $applications[$_]->{service} eq $caller and $applications[$_]->{path} eq $path;
		hsphfpd_unregister_application_i($_);
		return;
	}
	throw_dbus_error('org.hsphfpd.Error.DoesNotExist', qq(Application "$caller" "$path" is not registered));
}

sub hsphfpd_application_interfaces_added {
	my ($application, $path, $interfaces) = @_;
	return unless defined $path and defined $interfaces;
	return unless ref $path eq '' and ref $interfaces eq 'HASH';
	if (exists $interfaces->{'org.hsphfpd.AudioAgent'}) {{
		last unless ref $interfaces->{'org.hsphfpd.AudioAgent'} eq 'HASH';
		last unless exists $interfaces->{'org.hsphfpd.AudioAgent'}->{AgentCodec};
		my $codec = $interfaces->{'org.hsphfpd.AudioAgent'}->{AgentCodec};
		last unless ref $codec eq '' and $codec ne '';
		last if grep { $_->{path} eq $path } @{$application->{agents}};
		print "Registering application's " . $application->{service} . " " . $application->{path} . " audio agent $path for codec $codec\n";
		push @{$application->{agents}}, { type => 'audio', path => $path, codec => $codec };
	}}
	if (exists $interfaces->{'org.hsphfpd.TelephonyAgent'}) {{
		last unless ref $interfaces->{'org.hsphfpd.TelephonyAgent'} eq 'HASH';
		last unless exists $interfaces->{'org.hsphfpd.TelephonyAgent'}->{Role};
		my $role = $interfaces->{'org.hsphfpd.TelephonyAgent'}->{Role};
		last unless ref $role eq '' and $role =~ /^(?:gateway|client)$/;
		last if grep { $_->{path} eq $path } @{$application->{agents}};
		print "Registering application's " . $application->{service} . " " . $application->{path} . " telephony agent $path for role $role\n";
		push @{$application->{agents}}, { type => 'telephony', path => $path, role => $role };
		my $timer_id; # postpone connecting telephony agent after callback finish
		$timer_id = $reactor->add_timeout(0, sub {
			hsphfpd_connect_telephony($_) foreach sort keys %endpoints;
			$reactor->remove_timeout($timer_id);
		});
	}}
}

sub hsphfpd_application_interfaces_removed {
	my ($application, $path, $interfaces) = @_;
	return unless defined $path and defined $interfaces;
	return unless ref $path eq '' and ref $interfaces eq 'ARRAY';
	foreach (@{$interfaces}) {
		next unless ref $_ eq '';
		next unless $_ eq 'org.hsphfpd.AudioAgent' or $_ eq 'org.hsphfpd.TelephonyAgent';
		foreach (0..$#{$application->{agents}}) {
			next unless $application->{agents}->[$_]->{path} eq $path;
			print "Unregistering application's " . $application->{service} . " " . $application->{path} . " " . $application->{agents}->[$_]->{type} . " agent $path\n";
			splice @{$application->{agents}}, $_, 1;
			last;
		}
	}
}

sub hsphfpd_get_endpoints {
	return { map { $_ => { 'org.hsphfpd.Endpoint' => $endpoints{$_}->{properties} } } sort keys %endpoints };
}

sub hsphfpd_our_power_source {
	my ($new_source) = @_;
	return $our_power_source unless defined $new_source;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid value "$new_source", it must be in "battery", "external" or "unknown")) unless $new_source =~ /^(?:battery|external|unknown)$/;
	return if $our_power_source eq $new_source;
	$our_power_source = $new_source;
	print "Sending new power source $our_power_source\n";
	foreach my $endpoint (sort keys %endpoints) {
		if ($endpoints{$endpoint}->{profile} =~ /_ag$/) {
			if (exists $endpoints{$endpoint}->{csr_features}->{'csr-power-source'} and $endpoints{$endpoint}->{csr_features}->{'csr-power-source'}) {
				hsphfpd_csr_send_power_source($endpoint);
			}
			if (exists $endpoints{$endpoint}->{apple_features}->{'apple-battery-level'} and $our_power_source ne 'unknown') {
				# We map external power source to docked state and battery power source to undocked state
				hsphfpd_socket_write($endpoint, "AT+IPHONEACCEV=1,2," . (($our_power_source eq 'battery') ? 0 : 1));
			}
		}
	}
}

sub hsphfpd_our_battery_level {
	my ($new_level) = @_;
	return $our_battery_level unless defined $new_level;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid value "$new_level", it must be in range 0-100 or -1)) unless $new_level =~ /^(?:-1|[0-9]|[1-9][0-9]|100)$/;
	return if $our_battery_level eq $new_level;
	$our_battery_level = $new_level;
	print "Sending new battery level $our_battery_level\n";
	foreach my $endpoint (sort keys %endpoints) {
		next unless $endpoints{$endpoint}->{properties}->{Connected}->value();
		if ($endpoints{$endpoint}->{profile} =~ /_ag$/) {
			if (exists $endpoints{$endpoint}->{csr_features}->{'csr-battery-level'} and $endpoints{$endpoint}->{csr_features}->{'csr-battery-level'}) {
				hsphfpd_csr_send_battery_level($endpoint);
			}
			if (exists $endpoints{$endpoint}->{apple_features}->{'apple-battery-level'} and $our_battery_level != -1) {
				hsphfpd_socket_write($endpoint, "AT+IPHONEACCEV=1,1," . int(9 * $our_battery_level / 100 + 0.5));
			}
			if (exists $endpoints{$endpoint}->{hf_indicators}->{'battery-level'} and $our_battery_level != -1) {
				hsphfpd_socket_write($endpoint, "AT+BIEV=$hf_indicator_battery,$our_battery_level");
			}
		} else {
			if (exists $endpoints{$endpoint}->{ag_indicators}->{$ag_indicator_battchg} and $our_battery_level != -1) {
				hsphfpd_send_ag_battchg($endpoint);
			}
		}
	}
}

sub hsphfpd_connect_telephony {
	my ($endpoint) = @_;
	return unless $endpoints{$endpoint}->{properties}->{Connected}->value();
	return if exists $endpoints{$endpoint}->{telephony};
	print "Trying to connect some telephony agent for endpoint $endpoint\n";
	my $role = $endpoints{$endpoint}->{properties}->{Role}->value();
	my $properties = {
		Name => $endpoints{$endpoint}->{properties}->{Name},
		LocalAddress => $endpoints{$endpoint}->{properties}->{LocalAddress},
		RemoteAddress => $endpoints{$endpoint}->{properties}->{RemoteAddress},
		Profile => $endpoints{$endpoint}->{properties}->{Profile},
		Version => $endpoints{$endpoint}->{properties}->{Version},
		Features => $endpoints{$endpoint}->{properties}->{Features},
		(($role eq 'client') ? (Indicators => dbus_array([ map { dbus_string($ag_indicators{$_}->{name}) } sort { $a <=> $b } keys %ag_indicators ])) : ()),
	};
	my $telephony;
	my $connected;
	my $error;
	foreach (@applications) {
		my $path = $_->{path};
		my $service = $_->{service};
		foreach (@{$_->{agents}}) {
			next unless $_->{type} eq 'telephony';
			next unless $_->{role} eq $role;
			next if exists $_->{skip}->{$endpoint};
			print "Creating new telephony socket pair\n";
			# PF_UNIX => 1, SOCK_SEQPACKET = 5, PF_UNSPEC => 0, SOCK_NONBLOCK => 2048
			socketpair my $socket, my $agent_socket, 1, (5 | 2048), 0 or do {
				print "socketpair failed: $!\n";
				print "Not trying to contant Telephony agents\n";
				return;
			};
			print "Passing telephony socket to application's $service $path agent $_->{path}\n";
			my $agent = Net::DBus::RemoteService->new($bus, $service, $service)->get_object($_->{path}, 'org.hsphfpd.TelephonyAgent');
			eval { $agent->NewConnection(dbus_object_path($endpoint), dbus_unix_fd(fileno $agent_socket), $properties); $connected = 1; };
			close $agent_socket;
			if ($connected) {
				select((select($socket), $| = 1)[0]); # enable autoflush
				$telephony = { socket => $socket, application_service => $service, application_path => $path, agent_path => $_->{path} };
				last;
			}
			shutdown $socket, 2;
			close $socket;
			$error = 1;
			$_->{skip}->{$endpoint} = 1;
			print "Agent $service $_->{path} returned error: $@";
		}
		push @{$_->{telephonys}}, $endpoint if $connected;
		last if $connected;
	}
	if (not $connected) {
		if ($error) {
			print "All registered applications rejected telephony socket\n";
		} else {
			print "There is no application with telephony agent\n";
		}
		return;
	}
	$reactor->add_read(fileno $telephony->{socket}, sub { hsphfpd_telephony_ready_read($endpoint) });
	$reactor->add_exception(fileno $telephony->{socket}, sub { print "Socket exception on telephony for endpoint $endpoint\n"; hsphfpd_disconnect_telephony($endpoint) });
	$endpoints{$endpoint}->{telephony} = $telephony;
	print "Telephony connection for endpoint $endpoint is established\n";
	$endpoints{$endpoint}->{properties}->{TelephonyConnected} = dbus_boolean(1);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { TelephonyConnected => dbus_boolean(1) }, []);
	if ($role eq 'client') {
		# All indicators except battchg are handled by Telephony agent
		hsphfpd_telephony_write($endpoint, 'AT+BIA=' . join ',', map { ($ag_indicator_battchg != $_ and $endpoints{$endpoint}->{ag_indicators}->{$_}) ? 1 : 0 } sort { $a <=> $b } keys %ag_indicators) or return;
		hsphfpd_telephony_wait_for_ok_error($endpoint);
		if ($endpoints{$endpoint}->{ag_indicators_reporting}) {
			hsphfpd_telephony_write($endpoint, 'AT+CMER=3,0,0,1') or return;
			hsphfpd_telephony_wait_for_ok_error($endpoint);
		}
		if ($endpoints{$endpoint}->{ag_call_waiting_notifications}) {
			hsphfpd_telephony_write($endpoint, 'AT+CCWA=1') or return;
			hsphfpd_telephony_wait_for_ok_error($endpoint);
		}
		if ($endpoints{$endpoint}->{ag_extended_error_result_codes}) {
			hsphfpd_telephony_write($endpoint, 'AT+CMEE=1') or return;
			hsphfpd_telephony_wait_for_ok_error($endpoint);
		}
	} else {
		# TODO: implement HFP AG role
	}
}

sub hsphfpd_telephony_write {
	my ($endpoint, $line, $raw) = @_;
	print "Telephony write: endpoint=$endpoint\n";
	if (not $raw) {
		print "Line: $line\n";
		if ($endpoints{$endpoint}->{profile} =~ /_ag$/) {
			$line = "\r\n$line\r\n";
		} else {
			$line .= "\r";
		}
	}
	my $socket = $endpoints{$endpoint}->{telephony}->{socket};
	my $success = eval { print $socket $line };
	if (not $success) {
		my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
		print "Write error: $error";
		hsphfpd_disconnect_telephony($endpoint);
	}
	return $success;
}

sub hsphfpd_telephony_wait_for_ok_error {
	my ($endpoint) = @_;
	my $fd = fileno $endpoints{$endpoint}->{telephony}->{socket};
	# wait maximally 10 seconds and read maximally 20 lines
	for (1..20) {
		my $rfds = '';
		vec($rfds, $fd, 1) = 1;
		my $efds = $rfds;
		my $nfound = select $rfds, undef, $efds, 10;
		return 0 if $nfound <= 0 or vec $efds, $fd, 1;
		my $ret = hsphfpd_telephony_ready_read($endpoint, 1);
		return $ret if defined $ret;
	}
	return 0;
}

sub hsphfpd_telephony_ready_read {
	my ($endpoint, $ok_error_no_forward) = @_;
	print "Telephony ready read: endpoint=$endpoint\n";
	my $is_ag = ($endpoints{$endpoint}->{profile} =~ /_ag$/ ? 1 : 0);
	my $socket = $endpoints{$endpoint}->{telephony}->{socket};
	while (1) { # Due to buffered read we need to process all lines before existing this function
		my $origline = eval { local $/ = ($is_ag ? "\r" : "\n"); <$socket> };
		if (not defined $origline) {
			last if $!{EAGAIN};
			my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
			print "Read error: $error";
			hsphfpd_disconnect_telephony($endpoint);
			return;
		}
		my $line = $origline;
		$line =~ s/^\s*//;
		$line =~ s/\s*$//;
		if (not length $line) {
			hsphfpd_socket_write($endpoint, $origline, 1) unless $ok_error_no_forward;
			next;
		}
		print "Line: $line\n";
		if ($endpoints{$endpoint}->{profile} =~ /_ag$/) {
			hsphfpd_socket_write($endpoint, $origline, 1);
		} else {
			if ($line =~ /^\+CIND:\s*((?:[0-9]+)(?:,\s*(?1))?)$/) {
				my @values = map { int($_) } split /,/, $1;
				if (@values >= $ag_indicator_battchg) {
					# All indicators except battchg are handled by Telephony agent
					$values[$ag_indicator_battchg-1] = ($our_battery_level != -1) ? int(5 * $our_battery_level / 100 + 0.5) : 0;
				}
				my $new_values = join ',', @values;
				hsphfpd_socket_write($endpoint, "+CIND: $new_values");
			} elsif ($line =~ /^\+CIEV:\s*0*\Q$ag_indicator_battchg\E,\s*[0-9]+$/) {
				# All indicators except battchg are handled by Telephony agent
				hsphfpd_send_ag_battchg($endpoint) if exists $endpoints{$endpoint}->{ag_indicators}->{$ag_indicator_battchg} and $our_battery_level != -1;
			} else {
				if ($ok_error_no_forward) {
					return 1 if $line eq 'OK';
					return 0 if $line eq 'ERROR';
				}
				hsphfpd_socket_write($endpoint, $origline, 1);
			}
		}
	}
	return;
}

sub hsphfpd_disconnect_telephony {
	my ($endpoint) = @_;
	return unless exists $endpoints{$endpoint}->{telephony};
	print "Disconnecting telephony agent from endpoint $endpoint\n";
	my $telephony = $endpoints{$endpoint}->{telephony};
	$reactor->remove_read(fileno $telephony->{socket});
	$reactor->remove_exception(fileno $telephony->{socket});
	shutdown $telephony->{socket}, 2;
	close $telephony->{socket};
	my $application_service = $telephony->{application_service};
	my $application_path = $telephony->{application_path};
	foreach (@applications) {
		next unless exists $_->{service} and $_->{service} eq $application_service;
		next unless exists $_->{path} and $_->{path} eq $application_path;
		$_->{telephonys} = [ grep { $_ ne $endpoint } @{$_->{telephonys}} ];
	}
	delete $endpoints{$endpoint}->{telephony};
	$endpoints{$endpoint}->{properties}->{TelephonyConnected} = dbus_boolean(0);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { TelephonyConnected => dbus_boolean(0) }, []);
}

sub hsphfpd_set_sco_codec {
	my ($socket, $air_codec, $agent_codec) = @_;
	if ($air_codec eq 'CVSD' and $agent_codec eq 'PCM_s16le_8kHz') {
		# SOL_BLUETOOTH => 274, BT_VOICE => 11, struct bt_voice { uint16_t setting; }
		setsockopt $socket, 274, 11, pack 'S', 0x0060 or print "Cannot set codec on SCO socket: $!\n"; # Ignore error as CVSD is default codec
	} elsif ($air_codec eq 'mSBC' and $agent_codec eq 'mSBC') {
		# SOL_BLUETOOTH => 274, BT_VOICE => 11, struct bt_voice { uint16_t setting; }
		setsockopt $socket, 274, 11, pack 'S', 0x0003 or return;
	} else {
		# TODO: add support for setting other SCO codecs via:
		# SOL_BLUETOOTH => 274, BT_VOICE_SETUP => 14, ...
		# But this is not implemented in kernel yet
		$!{EINVAL} = 1;
		return;
	}
	return 1;
}

sub hsphfpd_get_bluetooth_address {
	my ($packed_address) = @_;
	# AF_BLUETOOTH => 31, struct sockaddr_sco { sa_family_t sco_family; bdaddr_t sco_bdaddr; }, sa_family_t = uint16_t, bdaddr_t = uint8_t[6] (in reverse order)
	my ($family, @address) = unpack 'S(H2)6', $packed_address;
	return unless defined $family and $family == 31;
	return unless @address == 6 and length $packed_address == 8;
	return uc join ':', reverse @address;
}

sub hsphfpd_accept_audio {
	print "Accepting new audio transport\n";
	my $socket;
	my $packed_remote_address = accept $socket, $sco_listening_socket;
	if (not defined $packed_remote_address) {
		print "Accepting new audio transport failed: $!\n";
		return;
	}
	my $local_address = hsphfpd_get_bluetooth_address(getsockname($socket));
	if (not defined $local_address) {
		print "Audio transport has unknown local address, closing it\n";
		shutdown $socket, 2;
		close $socket;
		return;
	}
	my $remote_address = hsphfpd_get_bluetooth_address($packed_remote_address);
	if (not defined $remote_address) {
		print "Audio transport has unknown remote address, closing it\n";
		shutdown $socket, 2;
		close $socket;
		return;
	}
	print "Local address is $local_address and remote address is $remote_address\n";
	my @candidates;
	my $device;
	foreach (sort keys %endpoints) {
		next unless uc $endpoints{$_}->{properties}->{RemoteAddress}->value() eq uc $remote_address;
		next unless uc $endpoints{$_}->{properties}->{LocalAddress}->value() eq uc $local_address;
		next unless $endpoints{$_}->{properties}->{Connected}->value();
		if ($endpoints{$_}->{properties}->{AudioConnected}->value()) {
			print "Audio transport for device $remote_address is already in use\n";
			shutdown $socket, 2;
			close $socket;
			return;
		}
		# Prefer Audio Gateway endpoints
		if ($endpoints{$_}->{profile} =~ /_ag$/) {
			unshift @candidates, $_;
		} else {
			push @candidates, $_;
		}
		$device = $endpoints{$_}->{device} unless defined $device;
	}
	if (not @candidates) {
		print "Device $remote_address does not have any connected endpoint, closing audio transport\n";
		shutdown $socket, 2;
		close $socket;
		return;
	}
	# Choose candidate which negotiated codec settings recently or connected recently; otherwise fallback to first candidate
	my ($endpoint) = grep { $endpoints{$_}->{profile} eq $devices{$device}->{selected_profile} } @candidates;
	$endpoint //= $candidates[0];
	my $adapter = $devices{$endpoints{$endpoint}->{device}}->{adapter};
	my $air_codec = $endpoints{$endpoint}->{selected_codec};
	my $agent_codecs = $adapters{$adapter}->{codecs}->{$air_codec};
	my $agent_codec;
	if (not $kernel_defer_support) {
		# Without defer setup, kernel already accepted SCO connection with CVSD air codec and PCM_s16le_8kHz agent codec
		if ($air_codec ne 'CVSD') {
			print "Selected air codec $air_codec is not supported by kernel\n";
			shutdown $socket, 2;
			close $socket;
			return;
		}
		if (not grep { $_ eq 'PCM_s16le_8kHz' } map { map { ($_->{type} eq 'audio' and exists $agent_codecs->{$_->{codec}}) ? $_->{codec} : () } @{$_->{agents}} } @applications) {
			print "There is no application with audio agent for agent codec PCM_s16le_8kHz\n";
			shutdown $socket, 2;
			close $socket;
			return;
		}
		print "Choosing agent codec PCM_s16le_8kHz\n";
		$agent_codec = 'PCM_s16le_8kHz';
		if (not eval { hsphfpd_establish_audio($endpoint, $socket, $agent_codec, @applications); 1 }) {
			shutdown $socket, 2;
			close $socket;
			return;
		}
	} else {
		($agent_codec) = map { map { ($_->{type} eq 'audio' and exists $agent_codecs->{$_->{codec}}) ? $_->{codec} : () } @{$_->{agents}} } @applications;
		if (not defined $agent_codec) {
			print "There is no application with audio agent and agent codec comapatile with air codec $air_codec\n";
			shutdown $socket, 2;
			close $socket;
			return;
		}
		print "Choosing agent codec $agent_codec\n";
		if (not hsphfpd_set_sco_codec($socket, $air_codec, $agent_codec)) {
			print "Cannot set codec on SCO socket: $!\n";
			shutdown $socket, 2;
			close $socket;
			return;
		}
		# NOTE: In deferred setup, accepted SCO socket is not connected yet.
		# Connecting SCO socket is done by reading non-zero buffer from socket.
		# Reading from such socket is always non-blocking and always returns zero length buffer.
		# When socket is really connected it is indicated by POLLOUT event.
		print "Connecting SCO socket for audio transport\n";
		my $buffer;
		sysread $socket, $buffer, 1;
		$reactor->add_exception(fileno $socket, sub {
			print "Connecting SCO socket failed\n";
			$reactor->remove_write(fileno $socket);
			$reactor->remove_exception(fileno $socket);
			shutdown $socket, 2;
			close $socket;
		});
		$reactor->add_write(fileno $socket, sub {
			print "SCO socket for audio transport is now connected\n";
			$reactor->remove_write(fileno $socket);
			$reactor->remove_exception(fileno $socket);
			if (not eval { hsphfpd_establish_audio($endpoint, $socket, $agent_codec, @applications); 1 }) {
				shutdown $socket, 2;
				close $socket;
			}
		});
	}
}

sub hsphfpd_connect_audio {
	my ($endpoint, $caller, $air_codec, $agent_codec) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Endpoint "$endpoint" does not exist)) unless exists $endpoints{$endpoint};
	throw_dbus_error('org.hsphfpd.Error.NotConnected', qq(Endpoint "$endpoint" is not connected yet)) unless $endpoints{$endpoint}->{properties}->{Connected}->value();
	throw_dbus_error('org.hsphfpd.Error.AlreadyConnected', qq(Audio transport for endpoint "$endpoint" is already connected)) if $endpoints{$endpoint}->{properties}->{AudioConnected}->value();
	throw_dbus_error('org.hsphfpd.Error.InProgress', qq(Establishing connection of audio transport for endpoint "$endpoint" is already in progress)) if exists $endpoints{$endpoint}->{audio};
	my $local_address = $endpoints{$endpoint}->{properties}->{LocalAddress}->value();
	my $remote_address = $endpoints{$endpoint}->{properties}->{RemoteAddress}->value();
	throw_dbus_error('org.hsphfpd.Error.InUse', qq(Audio transport for device "$remote_address" is already in use)) if grep { $_ ne $endpoint and lc $endpoints{$_}->{properties}->{RemoteAddress}->value() eq lc $remote_address and exists $endpoints{$_}->{audio} } keys %endpoints;
	my @sorted_applications = sort { ($a->{service} eq $caller) ? ($b->{service} eq $caller ? 0 : -1) : ($b->{service} eq $caller ? 1 : 0) } @applications;
	print "Connecting audio transport for endpoint $endpoint with air_codec $air_codec and agent_codec $agent_codec\n";
	my $adapter = $devices{$endpoints{$endpoint}->{device}}->{adapter};
	my $endpoint_codecs = $endpoints{$endpoint}->{codecs};
	my $air_codecs = $adapters{$adapter}->{codecs};
	if ($air_codec ne '') {
		throw_dbus_error('org.hsphfpd.Error.NotSupported', qq(Air codec "$air_codec" is not supported by endpoint)) unless exists $endpoint_codecs->{$air_codec};
		throw_dbus_error('org.hsphfpd.Error.NotSupported', qq(Air codec "$air_codec" is not supported by adapter)) unless exists $air_codecs->{$air_codec};
		throw_dbus_error('org.hsphfpd.Error.NotAvailable', qq(There is no application with audio agent)) unless grep { grep { $_->{type} eq 'audio' } @{$_->{agents}} } @sorted_applications;
		my $agent_codecs = $air_codecs->{$air_codec};
		if ($agent_codec ne '') {
			throw_dbus_error('org.hsphfpd.Error.NotSupported', qq(Air codec "$air_codec" with agent codec "$agent_codec" is not supported by adapter)) unless exists $agent_codecs->{$agent_codec};
			throw_dbus_error('org.hsphfpd.Error.NotAvailable', qq(There is no application with audio agent for agent codec "$agent_codec")) unless grep { grep { $_->{type} eq 'audio' and $_->{codec} eq $agent_codec } @{$_->{agents}} } @sorted_applications;
		} else {
			($agent_codec) = map { map { ($_->{type} eq 'audio' and exists $agent_codecs->{$_->{codec}}) ? $_->{codec} : () } @{$_->{agents}} } @sorted_applications;
			throw_dbus_error('org.hsphfpd.Error.NotAvailable', qq(There is no application with audio agent and agent codec comapatile with air codec "$air_codec")) unless defined $agent_codec;
			print "Choosing agent codec $agent_codec\n";
		}
	} else {
		my %rev_air_codecs;
		foreach my $rev (keys %{$air_codecs}) {
			$rev_air_codecs{$_}->{$rev} = 1 foreach keys %{$air_codecs->{$rev}};
		}
		throw_dbus_error('org.hsphfpd.Error.NotSupported', qq(Agent codec "$agent_codec" is not supported by adapter)) unless $agent_codec eq '' or exists $rev_air_codecs{$agent_codec};
		throw_dbus_error('org.hsphfpd.Error.NotAvailable', qq(There is no application with audio agent)) unless grep { grep { $_->{type} eq 'audio' } @{$_->{agents}} } @sorted_applications;
		my @all_agent_codecs = map { map { ($_->{type} eq 'audio') ? $_->{codec} : () } @{$_->{agents}} } @sorted_applications;
		@all_agent_codecs = grep { $_ eq $agent_codec } @all_agent_codecs if $agent_codec ne '';
		$air_codec = $endpoints{$endpoint}->{selected_codec};
		if ((not exists $adapters{$adapter}->{codecs}->{$air_codec}) or
		    ($agent_codec eq '' and not grep { grep { $_->{type} eq 'audio' and exists $air_codecs->{$air_codec}->{$_->{codec}} } @{$_->{agents}} } @sorted_applications) or
		    (not exists $air_codecs->{$air_codec}->{$agent_codec} or not grep { grep { $_->{type} eq 'audio' and $_->{codec} eq $agent_codec } @{$_->{agents}} } @sorted_applications)) {
			($air_codec) = grep { exists $endpoint_codecs->{$_} } map { exists $rev_air_codecs{$_} ? sort keys %{$rev_air_codecs{$_}} : () } @all_agent_codecs;
			throw_dbus_error('org.hsphfpd.Error.NotAvailable', ($agent_codec eq '') ? qq(There is no application with audio agent for agent codec supported by adapter) : qq(There is no application with audio agent for agent codec "$agent_codec")) unless defined $air_codec;
		}
		print "Choosing air codec $air_codec\n";
		if ($agent_codec eq '') {
			($agent_codec) = grep { exists $rev_air_codecs{$_} } @all_agent_codecs;
			print "Choosing agent codec $agent_codec\n";
		}
	}
	if ($endpoints{$endpoint}->{selected_codec} ne $air_codec) {
		my ($hf_codec_id) = grep { $hf_codecs_map{$_} eq $air_codec } keys %hf_codecs_map;
		if (defined $hf_codec_id) {
			print "Negotiating HF codec $air_codec\n";
			hsphfpd_socket_write($endpoint, "+BCS: $hf_codec_id") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		} else {
			print "Negotiating CSR codec $air_codec\n";
			my ($codec, $bandwidth);
			if ($air_codec =~ /^AuriStream_2bit_/) {
				$codec = 0b010;
			} elsif ($air_codec =~ /^AuriStream_4bit_/) {
				$codec = 0b100;
			}
			if ($air_codec =~ /_8kHz$/) {
				$bandwidth = 0b01;
			} elsif ($air_codec =~ /_16kHz$/) {
				$bandwidth = 0b10;
			}
			throw_dbus_error('org.hsphfpd.Error.Failed', "Unknown air codec $air_codec") unless defined $codec and defined $bandwidth;
			my $bandwidth_part = $endpoints{$endpoint}->{csr_bandwidths} ? ",(7,$bandwidth)" : '';
			hsphfpd_socket_write($endpoint, "+CSRFN: (6,$codec)$bandwidth_part") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		}
		$endpoints{$endpoint}->{codec_negotiation} = 1;
		my $success = hsphfpd_socket_wait_for_ok_error($endpoint);
		$endpoints{$endpoint}->{codec_negotiation} = 0;
		throw_dbus_error('org.hsphfpd.Error.Failed', qq(Codec connection setup for "$air_codec" failed)) unless $success and $endpoints{$endpoint}->{selected_codec} eq $air_codec;
	}
	if ($endpoints{$endpoint}->{profile} eq 'hfp_ag' and exists $endpoints{$endpoint}->{hf_features}->{'codec-negotiation'}) {
		# TODO: implement HFP AG role and establish audio connection via AT+BCC
	}
	print "Creating SCO socket\n";
	my $socket;
	# PF_BLUETOOTH => 31, SOCK_SEQPACKET => 5, BTPROTO_SCO => 2
	socket $socket, 31, 5, 2 or throw_dbus_error('org.hsphfpd.Error.Failed', qq(Opening SCO socket failed: $!));
	# AF_BLUETOOTH => 31, struct sockaddr_sco { sa_family_t sco_family; bdaddr_t sco_bdaddr; }, sa_family_t = uint16_t, bdaddr_t = uint8_t[6] (in reverse order)
	bind $socket, pack 'S(H2)6', 31, reverse split /:/, $local_address or throw_dbus_error('org.hsphfpd.Error.Failed', qq(Binding SCO socket to adapter "$local_address" failed: $!));
	hsphfpd_set_sco_codec($socket, $air_codec, $agent_codec) or throw_dbus_error('org.hsphfpd.Error.Failed', qq(Setting air codec to "$air_codec" and agent codec to "$agent_codec" on SCO socket failed: $!));
	connect $socket, pack 'S(H2)6', 31, reverse split /:/, $remote_address or throw_dbus_error('org.hsphfpd.Error.Failed', qq(Connecting SCO socket to device "$remote_address" failed: $!));
	return hsphfpd_establish_audio($endpoint, $socket, $agent_codec, @sorted_applications);
}

sub hsphfpd_establish_audio {
	my ($endpoint, $socket, $agent_codec, @sorted_applications) = @_;

	my $mtu;
	# SOL_SCO => 17, SCO_OPTIONS => 1, struct sco_options { uint16_t mtu; }
	my $value = getsockopt $socket, 17, 1;
	if (defined $value and length $value >= 2) {
		$mtu = unpack 'S', $value;
	} else {
		print "Reading MTU of SCO socket failed: $!\n";
		$mtu = 48;
	}

	my $air_codec = $endpoints{$endpoint}->{selected_codec};

	$fd_num++;
	my $audio = $endpoint;
	$audio =~ s{/[^/]*$}{/audio_fd$fd_num};

	my $hsphfpd_manager_path = $hsphfpd_manager->get_object_path();
	my $audio_suffix = $audio;
	$audio_suffix =~ s/^\Q$hsphfpd_manager_path\E//;

	$endpoints{$endpoint}->{audio} = $audio;
	$audios{$audio} = { endpoint => $endpoint, socket => $socket, mtu => $mtu, air_codec => $air_codec, agent_codec => $agent_codec };
	$audios{$audio}->{object} = main::Audio->new($hsphfpd_manager, $audio_suffix);
	$reactor->add_exception(fileno $socket, sub { print "Socket exception on audio transport $audio\n"; hsphfpd_disconnect_audio($audio) });

	print "Audio transport $audio created\n";

	my $properties = {
		RxVolumeControl => dbus_string($endpoints{$endpoint}->{rx_volume_control}),
		($endpoints{$endpoint}->{rx_volume_control} ne 'none') ? (
			RxVolumeGain => dbus_uint16($endpoints{$endpoint}->{rx_volume_gain}),
		) : (),
		TxVolumeControl => dbus_string($endpoints{$endpoint}->{tx_volume_control}),
		($endpoints{$endpoint}->{tx_volume_control} ne 'none') ? (
			TxVolumeGain => dbus_uint16($endpoints{$endpoint}->{tx_volume_gain}),
		) : (),
		MTU => dbus_uint16($mtu),
		Endpoint => dbus_object_path($endpoint),
		Name => $endpoints{$endpoint}->{properties}->{Name},
		LocalAddress => $endpoints{$endpoint}->{properties}->{LocalAddress},
		RemoteAddress => $endpoints{$endpoint}->{properties}->{RemoteAddress},
		Profile => $endpoints{$endpoint}->{properties}->{Profile},
		Version => $endpoints{$endpoint}->{properties}->{Version},
		Role => $endpoints{$endpoint}->{properties}->{Role},
		AirCodec => dbus_string($air_codec),
	};

	my $connected;
	my $canceled;
	my $error;
	foreach (@sorted_applications) {
		my $path = $_->{path};
		my $service = $_->{service};
		foreach (@{$_->{agents}}) {
			next unless $_->{type} eq 'audio';
			next unless $_->{codec} eq $agent_codec;
			print "Passing audio transport $audio to application's $service $path agent $_->{path} with codec $_->{codec}\n";
			my $agent = Net::DBus::RemoteService->new($bus, $service, $service)->get_object($_->{path}, 'org.hsphfpd.AudioAgent');
			eval { $agent->NewConnection(dbus_object_path($audio), dbus_unix_fd(fileno $socket), $properties); $connected = 1; };
			if ($connected) {
				$audios{$audio}->{agent_path} = $_->{path};
				$audios{$audio}->{application_path} = $path;
				$audios{$audio}->{application_service} = $service;
				last;
			}
			$error = 1;
			$canceled = 1 if ref $@ eq 'Net::DBus::Error' and $@->name eq 'org.hsphfpd.Error.Canceled';
			print "Agent $service $_->{path} returned error: $@";
			last if $canceled;
		}
		push @{$_->{audios}}, $audio if $connected;
		last if $canceled or $connected;
	}
	if (not $connected) {
		hsphfpd_disconnect_audio($audio);
		throw_dbus_error('org.hsphfpd.Error.Failed', $canceled ? qq(Audio application canceled SCO socket) : $error ? qq(All registered applications with audio agents rejected SCO socket) : qq(There is no application with audio agent));
	}

	print "Audio connection for transport $audio is established\n";
	$endpoints{$endpoint}->{properties}->{AudioConnected} = dbus_boolean(1);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { AudioConnected => dbus_boolean(1) }, []);

	return ($audio, $audios{$audio}->{application_service}, $audios{$audio}->{agent_path});
}

sub hsphfpd_disconnect_audio {
	my ($audio) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Audio transport "$audio" does not exist)) unless exists $audios{$audio};
	print "Disconnecting audio transport $audio\n";
	my $endpoint = $audios{$audio}->{endpoint};
	if (exists $endpoints{$endpoint}) {
		delete $endpoints{$endpoint}->{audio};
		$endpoints{$endpoint}->{properties}->{AudioConnected} = dbus_boolean(0);
		$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { AudioConnected => dbus_boolean(0) }, []);
	}
	$audios{$audio}->{object}->disconnect();
	print "Destroying SCO socket\n";
	$reactor->remove_exception(fileno $audios{$audio}->{socket});
	shutdown $audios{$audio}->{socket}, 2;
	close $audios{$audio}->{socket};
	if (exists $audios{$audio}->{application_service}) {
		my $application_service = $audios{$audio}->{application_service};
		my $application_path = $audios{$audio}->{application_path};
		foreach (@applications) {
			next unless exists $_->{service} and $_->{service} eq $application_service;
			next unless exists $_->{path} and $_->{path} eq $application_path;
			$_->{audios} = [ grep { $_ ne $audio } @{$_->{audios}} ];
		}
	}
	delete $audios{$audio};
}

sub hsphfpd_rx_volume_gain {
	my ($audio, $new_gain) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Audio transport "$audio" does not exist)) unless exists $audios{$audio};
	my $endpoint = $audios{$audio}->{endpoint};
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Rx volume control for audio transport "$audio" is not supported)) if $endpoints{$endpoint}->{rx_volume_control} eq 'none';
	return $endpoints{$endpoint}->{rx_volume_gain} unless defined $new_gain;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid value "$new_gain", it must be in range 0-15)) unless $new_gain =~ /^(?:[0-9]|1[0-5])$/;
	return if $endpoints{$endpoint}->{rx_volume_gain} == $new_gain;
	print "Setting rx volume gain to $new_gain for endpoint $endpoint\n";
	my $profile = $endpoints{$endpoint}->{profile};
	if ($profile eq 'hsp_hs') {
		hsphfpd_socket_write($endpoint, "+VGM=$new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
	} elsif ($profile eq 'hfp_hf') {
		hsphfpd_socket_write($endpoint, "+VGM: $new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
	} else {
		# AG role describes speaker as local receiving device
		hsphfpd_socket_write($endpoint, "AT+VGS=$new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		if (not hsphfpd_socket_wait_for_ok_error($endpoint)) {
			hsphfpd_rx_volume_control_changed($endpoint, 'none');
			throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		}
	}
	$endpoints{$endpoint}->{rx_volume_gain} = $new_gain;
	$audios{$audio}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { RxVolumeGain => dbus_uint16($new_gain) }, []);
}

sub hsphfpd_tx_volume_gain {
	my ($audio, $new_gain) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Audio transport "$audio" does not exist)) unless exists $audios{$audio};
	my $endpoint = $audios{$audio}->{endpoint};
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Tx volume control for audio transport "$audio" is not supported)) if $endpoints{$endpoint}->{tx_volume_control} eq 'none';
	return $endpoints{$endpoint}->{tx_volume_gain} unless defined $new_gain;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Invalid value "$new_gain", it must be in range 0-15)) unless $new_gain =~ /^(?:[0-9]|1[0-5])$/;
	return if $endpoints{$endpoint}->{tx_volume_gain} == $new_gain;
	print "Setting tx volume gain to $new_gain for endpoint $endpoint\n";
	my $profile = $endpoints{$endpoint}->{profile};
	if ($profile eq 'hsp_hs') {
		hsphfpd_socket_write($endpoint, "+VGS=$new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
	} elsif ($profile eq 'hfp_hf') {
		hsphfpd_socket_write($endpoint, "+VGS: $new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
	} else {
		# AG role describes microphone as local transmitting device
		hsphfpd_socket_write($endpoint, "AT+VGM=$new_gain") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		if (not hsphfpd_socket_wait_for_ok_error($endpoint)) {
			hsphfpd_tx_volume_control_changed($endpoint, 'none');
			throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
		}
	}
	$endpoints{$endpoint}->{tx_volume_gain} = $new_gain;
	$audios{$audio}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { TxVolumeGain => dbus_uint16($new_gain) }, []);
}

sub hsphfpd_send_ring_event {
	my ($endpoint) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Endpoint "$endpoint" does not exist)) unless exists $endpoints{$endpoint};
	throw_dbus_error('org.hsphfpd.Error.NotConnected', qq(Endpoint "$endpoint" is not connected yet)) unless $endpoints{$endpoint}->{properties}->{Connected}->value();
	print "Sending ring event for endpoint $endpoint\n";
	hsphfpd_socket_write($endpoint, 'RING') or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
}

sub hsphfpd_send_button_event {
	my ($endpoint) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Endpoint "$endpoint" does not exist)) unless exists $endpoints{$endpoint};
	throw_dbus_error('org.hsphfpd.Error.NotConnected', qq(Endpoint "$endpoint" is not connected yet)) unless $endpoints{$endpoint}->{properties}->{Connected}->value();
	print "Sending button press event for endpoint $endpoint\n";
	hsphfpd_socket_write($endpoint, 'AT+CKPD=200') or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
	hsphfpd_socket_wait_for_ok_error($endpoint) or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
}

sub hsphfpd_send_text_event {
	my ($endpoint, $text) = @_;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Endpoint "$endpoint" does not exist)) unless exists $endpoints{$endpoint};
	throw_dbus_error('org.hsphfpd.Error.NotConnected', qq(Endpoint "$endpoint" is not connected yet)) unless $endpoints{$endpoint}->{properties}->{Connected}->value();
	throw_dbus_error('org.hsphfpd.Error.NotSupported', qq(Endpoint "$endpoint" does not support "csr-display-text" feature)) unless exists $endpoints{$endpoint}->{csr_features}->{'csr-display-text'};
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Text message is too long, maximal size is 32 characters)) unless length $text <= 32;
	throw_dbus_error('org.hsphfpd.Error.InvalidArguments', qq(Text message cannot contain control characters)) if $text =~ /[\x00-\x1F]/;
	hsphfpd_socket_write($endpoint, "+CSRTXT: $text") or throw_dbus_error('org.hsphfpd.Error.Failed', 'Failed');
}

sub hsphfpd_send_ag_battchg {
	my ($endpoint) = @_;
	hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_battchg," . int(5 * $our_battery_level / 100 + 0.5));
}

sub hsphfpd_socket_write {
	my ($endpoint, $line, $raw) = @_;
	print "Socket write: endpoint=$endpoint\n";
	if (not $raw) {
		print "Line: $line\n";
		if ($endpoints{$endpoint}->{profile} =~ /_ag$/) {
			$line .= "\r";
		} else {
			$line = "\r\n$line\r\n";
		}
	}
	my $socket = $endpoints{$endpoint}->{socket};
	my $success = eval { print $socket $line };
	if (not $success) {
		my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
		print "Write error: $error";
		hsphfpd_disconnect_endpoint($endpoint);
	}
	return $success;
}

sub hsphfpd_socket_wait_for_ok_error {
	my ($endpoint) = @_;
	my $fd = fileno $endpoints{$endpoint}->{socket};
	# wait maximally 10 seconds and read maximally 20 lines
	for (1..20) {
		my $rfds = '';
		vec($rfds, $fd, 1) = 1;
		my $efds = $rfds;
		my $nfound = select $rfds, undef, $efds, 10;
		return 0 if $nfound <= 0 or vec $efds, $fd, 1;
		my $ret = hsphfpd_socket_ready_read($endpoint);
		return $ret if defined $ret;
	}
	return;
}

sub hsphfpd_rx_volume_control_changed {
	my ($endpoint, $new_volume_control) = @_;
	if (exists $endpoints{$endpoint}->{audio}) {
		my $access = ($new_volume_control eq 'none') ? 'write' : 'readwrite'; # write access will hide property in GetAll() method
		$audios{$endpoints{$endpoint}->{audio}}->{object}->{introspector}->{interfaces}->{'org.hsphfpd.AudioTransport'}->{props}->{RxVolumeGain}->{access} = $access;
		if ($endpoints{$endpoint}->{rx_volume_control} ne $new_volume_control) {
			if ($new_volume_control eq 'none') {
				$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { RxVolumeControl => dbus_string($new_volume_control) }, [ dbus_string('RxVolumeGain') ]);
			} else {
				$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { RxVolumeControl => dbus_string($new_volume_control), RxVolumeGain => dbus_uint16($endpoints{$endpoint}->{rx_volume_gain}) }, []);
			}
		}
	}
	$endpoints{$endpoint}->{rx_volume_control} = $new_volume_control;
}

sub hsphfpd_tx_volume_control_changed {
	my ($endpoint, $new_volume_control) = @_;
	if (exists $endpoints{$endpoint}->{audio}) {
		my $access = ($new_volume_control eq 'none') ? 'write' : 'readwrite'; # write access will hide property in GetAll() method
		$audios{$endpoints{$endpoint}->{audio}}->{object}->{introspector}->{interfaces}->{'org.hsphfpd.AudioTransport'}->{props}->{TxVolumeGain}->{access} = $access;
		if ($endpoints{$endpoint}->{tx_volume_control} ne $new_volume_control) {
			if ($new_volume_control eq 'none') {
				$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { TxVolumeControl => dbus_string($new_volume_control) }, [ dbus_string('TxVolumeGain') ]);
			} else {
				$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { TxVolumeControl => dbus_string($new_volume_control), TxVolumeGain => dbus_uint16($endpoints{$endpoint}->{tx_volume_gain}) }, []);
			}
		}
	}
	$endpoints{$endpoint}->{tx_volume_control} = $new_volume_control;
}

sub hsphfpd_tx_volume_gain_changed {
	my ($endpoint, $new_gain) = @_;
	$new_gain = 0 if $new_gain < 0;
	$new_gain = 15 if $new_gain > 15;
	return if $endpoints{$endpoint}->{tx_volume_gain} == $new_gain;
	print "Setting tx volume gain to $new_gain\n";
	$endpoints{$endpoint}->{tx_volume_gain} = $new_gain;
	$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { TxVolumeGain => dbus_uint16($new_gain) }, []) if exists $endpoints{$endpoint}->{audio};
}

sub hsphfpd_rx_volume_gain_changed {
	my ($endpoint, $new_gain) = @_;
	$new_gain = 0 if $new_gain < 0;
	$new_gain = 15 if $new_gain > 15;
	return if $endpoints{$endpoint}->{rx_volume_gain} == $new_gain;
	print "Setting rx volume gain to $new_gain\n";
	$endpoints{$endpoint}->{rx_volume_gain} = $new_gain;
	$audios{$endpoints{$endpoint}->{audio}}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.AudioTransport', { RxVolumeGain => dbus_uint16($new_gain) }, []) if exists $endpoints{$endpoint}->{audio};
}

sub hsphfpd_button_pressed {
	my ($endpoint) = @_;
	print "Button pressed event\n";
	return unless exists $endpoints{$endpoint}->{uinput};
	# struct input_event { struct timeval time; uint16_t type; uint16_t code; int32_t value; }, struct timeval { long tv_sec; long tv_usec; }, EV_KEY => 1, KEY_PHONE => 169, EV_SYN => 0, SYN_REPORT => 0
	syswrite $endpoints{$endpoint}->{uinput}, pack 'l!l!SSl', 0, 0, 1, 169, 1;
	syswrite $endpoints{$endpoint}->{uinput}, pack 'l!l!SSl', 0, 0, 0, 0, 0;
	syswrite $endpoints{$endpoint}->{uinput}, pack 'l!l!SSl', 0, 0, 1, 169, 0;
	syswrite $endpoints{$endpoint}->{uinput}, pack 'l!l!SSl', 0, 0, 0, 0, 0;
}

sub hsphfpd_update_features {
	my ($endpoint) = @_;
	my %features = map { $_ => 1 } keys %{$endpoints{$endpoint}->{csr_features}}, keys %{$endpoints{$endpoint}->{hf_features}}, keys %{$endpoints{$endpoint}->{ag_features}}, keys %{$endpoints{$endpoint}->{apple_features}}, keys %{$endpoints{$endpoint}->{hf_indicators}};
	$features{'volume-control'} = 1 if $endpoints{$endpoint}->{hs_volume_control};
	$features{'wide-band-speech'} = 1 if $endpoints{$endpoint}->{hfp_wide_band_speech};
	$endpoints{$endpoint}->{properties}->{Features} = dbus_array([ map { dbus_string($_) } sort keys %features ]);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { Features => $endpoints{$endpoint}->{properties}->{Features} }, []);
}

sub hsphfpd_update_codecs {
	my ($endpoint) = @_;
	my %codecs = map { $_ => 1 } @{$endpoints{$endpoint}->{csr_codecs}}, @{$endpoints{$endpoint}->{hf_codecs}};
	$codecs{CVSD} = 1 unless keys %codecs;
	$endpoints{$endpoint}->{codecs} = \%codecs;
	$endpoints{$endpoint}->{properties}->{AudioCodecs} = dbus_array([ map { dbus_string($_) } sort keys %codecs ]);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { AudioCodecs => $endpoints{$endpoint}->{properties}->{AudioCodecs} }, []);
}

sub hsphfpd_csr_codecs_changed {
	my ($endpoint, $codecs, $bandwidths) = @_;
	# Default value for CSR codecs (only CVSD) and bandwidths (only 16kHz)
	$codecs //= $endpoints{$endpoint}->{csr_last_codecs} // 0b001;
	$bandwidths //= $endpoints{$endpoint}->{csr_last_bandwidths} // 0b10;
	my @csr_codecs;
	push @csr_codecs, 'CVSD' if $codecs & 0b001;
	push @csr_codecs, 'AuriStream_2bit_8kHz' if $codecs & 0b010 and $bandwidths & 0b01;
	push @csr_codecs, 'AuriStream_2bit_16kHz' if $codecs & 0b010 and $bandwidths & 0b10;
	push @csr_codecs, 'AuriStream_4bit_8kHz' if $codecs & 0b100 and $bandwidths & 0b01;
	push @csr_codecs, 'AuriStream_4bit_16kHz' if $codecs & 0b100 and $bandwidths & 0b10;
	print "Supported CSR codecs:\n" . (join "\n", @csr_codecs) . "\n";
	$endpoints{$endpoint}->{csr_last_codecs} = $codecs;
	$endpoints{$endpoint}->{csr_last_bandwidths} = $bandwidths;
	$endpoints{$endpoint}->{csr_codecs} = \@csr_codecs;
	hsphfpd_update_codecs($endpoint);
}

sub hsphfpd_csr_power_source_changed {
	my ($endpoint, $source) = @_;
	print "CSR power source changed\n";
	$endpoints{$endpoint}->{properties}->{PowerSource} = dbus_string(($source == 1) ? 'battery' : ($source == 2) ? 'external' : 'unknown');
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { PowerSource => $endpoints{$endpoint}->{properties}->{PowerSource} }, []);
}

sub hsphfpd_csr_battery_level_changed {
	my ($endpoint, $level) = @_;
	print "CSR battery level changed\n";
	# CSR battery level is only in range 0-9 but HF battery level is range 0-100, so prefer usage of HF
	return if exists $endpoints{$endpoint}->{hf_indicators}->{'battery-level'};
	$endpoints{$endpoint}->{properties}->{BatteryLevel} = dbus_int16(($level >= 0 && $level <= 9) ? ($level * 100 / 9) : -1);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { BatteryLevel => $endpoints{$endpoint}->{properties}->{BatteryLevel} }, []);
}

sub hsphfpd_csr_supported_features {
	my ($endpoint, $caller_name, $raw_text, $sms_ind, $batt_level, $pwr_source, $codecs, $bandwidths) = @_;
	my %csr_features;
	$csr_features{'csr-caller-name'} = 1 if $caller_name;
	$csr_features{'csr-display-text'} = 1 if $raw_text;
	$csr_features{'csr-sms-indication'} = 1 if $sms_ind;
	$csr_features{'csr-battery-level'} = 1 if $batt_level;
	$csr_features{'csr-power-source'} = 1 if $pwr_source;
	print "Supported CSR features:\n" . (join "\n", sort keys %csr_features) . "\n";
	$endpoints{$endpoint}->{csr_features} = \%csr_features;
	$endpoints{$endpoint}->{csr_bandwidths} = defined $bandwidths ? 1 : 0;
	hsphfpd_update_features($endpoint);
	hsphfpd_csr_codecs_changed($endpoint, $codecs, $bandwidths);
	hsphfpd_csr_power_source_changed($endpoint, 0) unless $pwr_source;
	hsphfpd_csr_battery_level_changed($endpoint, -1) unless $batt_level;
	return unless defined wantarray;
	# In HSP profile we do not support telephony functions
	my $is_hsp = ($endpoints{$endpoint}->{profile} =~ /^hsp_/);
	return join ',', (
		((!$is_hsp and $caller_name) ? 1 : 0),
		($raw_text ? 1 : 0),
		((!$is_hsp and $sms_ind) ? 1 : 0),
		($batt_level ? 1 : 0),
		($pwr_source ? 1 : 0),
		((defined $codecs) ? int($codecs & 0b111) : ()),
		((defined $bandwidths) ? int($bandwidths & 0b11) : ()),
	);
}

sub hsphfpd_csr_indicators_changed {
	my ($endpoint, $indicators) = @_;
	print "CSR indicators changed\n";
	my $is_ag = ($endpoints{$endpoint}->{profile} =~ /_ag$/);
	my $codecs;
	my $bandwidths;
	my $features_changed;
	my @csr_features_map = qw(zero-index csr-caller-name csr-display-text csr-sms-indication csr-battery-level csr-power-source);
	foreach ($indicators =~ /\(([0-9]+,\s*[0-9]+)\)/g) {
		my ($ind, $val) = split /,\s*/, $_;
		if ($ind >= 1 and $ind <= $#csr_features_map) {
			my $csr_feature = $csr_features_map[$ind];
			if ($val and not exists $endpoints{$endpoint}->{csr_features}->{$csr_feature}) {
				print "Adding CSR feature: $csr_feature\n";
			}
			if ($val and not $endpoints{$endpoint}->{csr_features}->{$csr_feature}) {
				print "Enabling CSR indicator: $csr_feature\n";
				$endpoints{$endpoint}->{csr_features}->{$csr_feature} = 1;
				if ($is_ag) {
					hsphfpd_csr_send_battery_level($endpoint) if $csr_feature eq 'csr-battery-level';
					hsphfpd_csr_send_power_source($endpoint) if $csr_feature eq 'csr-power-source';
				}
				$features_changed = 1;
			} elsif (not $val and exists $endpoints{$endpoint}->{csr_features}->{$csr_feature} and $endpoints{$endpoint}->{csr_features}->{$csr_feature}) {
				print "Disabling CSR indicator: $csr_feature\n";
				$endpoints{$endpoint}->{csr_features}->{$csr_feature} = 0;
				if (not $is_ag) {
					hsphfpd_csr_power_source_changed($endpoint, 0) if $csr_feature eq 'csr-battery-level';
					hsphfpd_csr_battery_level_changed($endpoint, -1) if $csr_feature eq 'csr-power-source'
				};
				$features_changed = 1;
			}
		} elsif ($ind == 6) {
			$codecs = $val;
		} elsif ($ind == 7) {
			$bandwidths = $val;
			$endpoints{$endpoint}->{csr_bandwidths} = 1;
		} else {
			print "Unknown indicator $ind\n";
		}
	}
	hsphfpd_update_features($endpoint) if $features_changed;
	hsphfpd_csr_codecs_changed($endpoint, $codecs, $bandwidths) if defined $codecs or defined $bandwidths;
}

sub hsphfpd_csr_disable {
	my ($endpoint) = @_;
	print "Disabling all CSR indicators\n";
	$_ = 0 foreach values %{$endpoints{$endpoint}->{csr_features}};
	hsphfpd_update_features($endpoint);
	hsphfpd_csr_codecs_changed($endpoint, 0, 0);
}

sub hsphfpd_csr_select_codec {
	my ($endpoint, $codec, $bandwidth) = @_;
	print "Request for changing CSR codec\n";
	my $has_bandwidth = defined $bandwidth;
	$bandwidth //= 0b10;
	my $profile = $endpoints{$endpoint}->{profile};
	my $selected_codec;
	if ($codec == 0b001) {
		$selected_codec = 'CVSD';
	} elsif ($codec == 0b010 and $bandwidth == 0b01) {
		$selected_codec = 'AuriStream_2bit_8kHz';
	} elsif ($codec == 0b010 and $bandwidth == 0b10) {
		$selected_codec = 'AuriStream_2bit_16kHz';
	} elsif ($codec == 0b100 and $bandwidth == 0b01) {
		$selected_codec = 'AuriStream_4bit_8kHz';
	} elsif ($codec == 0b100 and $bandwidth == 0b10) {
		$selected_codec = 'AuriStream_4bit_16kHz';
	}
	my $adapter = $devices{$endpoints{$endpoint}->{device}}->{adapter};
	my $air_codecs = $adapters{$adapter}->{codecs};
	undef $selected_codec unless defined $selected_codec and exists $air_codecs->{$selected_codec} and grep { grep { $_->{type} eq 'audio' and exists $air_codecs->{$selected_codec}->{$_->{codec}} } @{$_->{agents}} } @applications;
	if (not defined $selected_codec) {
		print "Requested codec is not supported\n";
		if ($endpoints{$endpoint}->{codec_negotiation}) {
			hsphfpd_socket_write($endpoint, 'OK') or return;
			return 0;
		}
		if ($profile =~ /_ag$/) {
			if (defined $has_bandwidth) {
				hsphfpd_socket_write($endpoint, 'AT+CSRFN=(6,0),(7,0)') or return;
			} else {
				hsphfpd_socket_write($endpoint, 'AT+CSRFN=(6,0)') or return;
			}
		} else {
			if (defined $has_bandwidth) {
				hsphfpd_socket_write($endpoint, '+CSRFN: (6,0),(7,0)') or return;
			} else {
				hsphfpd_socket_write($endpoint, '+CSRFN: (6,0)') or return;
			}
			hsphfpd_socket_write($endpoint, 'ERROR') or return;
		}
		return;
	}
	print "Selected CSR codec is $selected_codec\n";
	$endpoints{$endpoint}->{selected_codec} = $selected_codec;
	$devices{$endpoints{$endpoint}->{device}}->{selected_profile} = $endpoints{$endpoint}->{profile};
	if ($endpoints{$endpoint}->{codec_negotiation}) {
		hsphfpd_socket_write($endpoint, 'OK') or return;
		return 1;
	}
	if ($profile =~ /_ag$/) {
		if (defined $has_bandwidth) {
			hsphfpd_socket_write($endpoint, "AT+CSRFN=(6,$codec),(7,$bandwidth)") or return;
		} else {
			hsphfpd_socket_write($endpoint, "AT+CSRFN=(6,$codec)") or return;
		}
	} else {
		if (defined $has_bandwidth) {
			hsphfpd_socket_write($endpoint, "+CSRFN: (6,$codec),(7,$bandwidth)") or return;
		} else {
			hsphfpd_socket_write($endpoint, "+CSRFN: (6,$codec)") or return;
		}
		hsphfpd_socket_write($endpoint, 'OK') or return;
	}
}

sub hsphfpd_csr_send_battery_level {
	my ($endpoint) = @_;
	if ($our_battery_level != -1) {
		if ($endpoints{$endpoint}->{ag_csr_battery_disabled}) {
			$endpoints{$endpoint}->{ag_csr_battery_disabled} = 0;
			hsphfpd_socket_write($endpoint, 'AT+CSR=(4,1)') or return;
			hsphfpd_socket_wait_for_ok_error($endpoint);
		}
		hsphfpd_socket_write($endpoint, 'AT+CSRBATT=' . int((9 * $our_battery_level / 100) + 0.5)) or return;
	} else {
		if (not $endpoints{$endpoint}->{ag_csr_battery_disabled}) {
			$endpoints{$endpoint}->{ag_csr_battery_disabled} = 1;
			hsphfpd_socket_write($endpoint, 'AT+CSR=(4,0)') or return;
			hsphfpd_socket_wait_for_ok_error($endpoint);
		}
	}
}

sub hsphfpd_csr_send_power_source {
	my ($endpoint) = @_;
	if ($our_power_source ne 'unknown') {
		if ($endpoints{$endpoint}->{ag_csr_power_disabled}) {
			$endpoints{$endpoint}->{ag_csr_power_disabled} = 0;
			hsphfpd_socket_write($endpoint, 'AT+CSR=(5,1)') or return;
			hsphfpd_socket_wait_for_ok_error($endpoint);
		}
		hsphfpd_socket_write($endpoint, "AT+CSRPWR=" . (($our_power_source eq 'battery') ? 1 : 2)) or return;
	} else {
		if (not $endpoints{$endpoint}->{ag_csr_power_disabled}) {
			$endpoints{$endpoint}->{ag_csr_power_disabled} = 1;
			hsphfpd_socket_write($endpoint, 'AT+CSR=(5,0)') or return;
			hsphfpd_socket_wait_for_ok_error($endpoint);
		}
	}
}

sub hsphfpd_socket_ready_read {
	my ($endpoint) = @_;
	print "Socket ready read: endpoint=$endpoint\n";
	my $socket = $endpoints{$endpoint}->{socket};
	my $is_ag = ($endpoints{$endpoint}->{profile} =~ /_ag$/ ? 1 : 0);
	while (1) { # Due to buffered read we need to process all lines before existing this function
		my $origline = eval { local $/ = ($is_ag ? "\n" : "\r"); <$socket> };
		if (not defined $origline) {
			last if $!{EAGAIN};
			my $error = $! ? "$!\n" : $@ ? "$@" : "unknown error\n";
			print "Read error: $error";
			hsphfpd_disconnect_endpoint($endpoint);
			return;
		}
		my $line = $origline;
		$line =~ s/^\s*//;
		$line =~ s/\s*$//;
		if (not length $line) {
			hsphfpd_telephony_write($endpoint, $origline, 1) if exists $endpoints{$endpoint}->{telephony};
			next unless length $line; # sometimes we may receive empty line (due to usage of LF and CRLF)
		}
		print "Line: $line\n";
		my $profile = $endpoints{$endpoint}->{profile};
		if ($profile eq 'hsp_hs') {
			# Some HSP devices really send +VGS= and +VGM= commands without AT prefix
			if ($line =~ /^(?:AT)?\+VGS=([0-9]+)$/) {
				my $new_gain = $1;
				hsphfpd_tx_volume_control_changed($endpoint, 'remote');
				hsphfpd_tx_volume_gain_changed($endpoint, $new_gain);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^(?:AT)?\+VGM=([0-9]+)$/) {
				my $new_gain = $1;
				hsphfpd_rx_volume_control_changed($endpoint, 'remote');
				hsphfpd_rx_volume_gain_changed($endpoint, $new_gain);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line eq 'AT+CKPD=200') {
				hsphfpd_button_pressed($endpoint);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRSF=([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+)(?:,\s*([0-9]+)(?:,\s*([0-9]+))?)?/) {
				my $response = hsphfpd_csr_supported_features($endpoint, $1, $2, $3, $4, $5, $6, $7);
				hsphfpd_socket_write($endpoint, "+CSRSF: $response") or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
				hsphfpd_socket_write($endpoint, '+CSRPWR?') if exists $endpoints{$endpoint}->{csr_features}->{'csr-power-source'};
				hsphfpd_socket_write($endpoint, '+CSRBATT?') if exists $endpoints{$endpoint}->{csr_features}->{'csr-battery-level'};
			} elsif ($line eq 'AT+CSR=0') {
				hsphfpd_csr_disable($endpoint);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSR=(\([0-9]+,\s*[0-9]+\)(?:,\s*(?1))?)$/) {
				hsphfpd_csr_indicators_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRFN=\(6,\s*([0-9]+)\)(?:,\(7,\s*([0-9]+)\))?$/) {
				hsphfpd_csr_select_codec($endpoint, $1, $2);
			} elsif ($line =~ /^AT\+CSRBATT=([0-9])$/) {
				hsphfpd_csr_battery_level_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRPWR=([1-2])$/) {
				hsphfpd_csr_power_source_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRGETSMS=([0-9]+)$/) {
				# In HSP mode we do not support telephony functions
				print "Requested for content of SMS with index $1 but telephony functions are not supported in HSP profile\n";
				hsphfpd_socket_write($endpoint, 'ERROR') or return;
			} elsif ($line =~ /^AT\+XAPL=[0-9A-Fa-f]+-[0-9A-Fa-f]+-[^\n\r,]+,\s*([0-9]+)$/) {
				my $apple_features = int($1);
				print "Apple features changed event\n";
				my %apple_features;
				foreach (sort { $a <=> $b } keys %apple_features_mask) { $apple_features{$apple_features_mask{$_}} = 1 if $apple_features & int($_); }
				print "Supported Apple features:\n" . (join "\n", sort keys %apple_features) . "\n";
				$endpoints{$endpoint}->{apple_features} = \%apple_features;
				hsphfpd_update_features($endpoint);
				hsphfpd_socket_write($endpoint, "+XAPL=iPhone," . int(0b11110)) or return;
			} elsif ($line =~ /^AT\+IPHONEACCEV=([0-9]+)(,\s*[0-9]+,\s*[0-9]+(?2)?)?$/) {
				my ($count, $indicators) = ($1, $2);
				print "Apple indicators changed event\n";
				my @indicators = ($indicators =~ /([0-9]+,\s*[0-9]+)/g);
				if (scalar @indicators != $count) {
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				} else {
					foreach (@indicators) {
						my ($key, $val) = split /,\s*/, $_;
						if ($key == 1 and $val >=0 and $val <= 9) {
							print "Apple battery level changed\n";
							# Apple battery level is only in range 0-9 but HF battery level is range 0-100, so prefer usage of HF
							if (not exists $endpoints{$endpoint}->{hf_indicators}->{'battery-level'}) {
								$endpoints{$endpoint}->{properties}->{BatteryLevel} = dbus_int16(($val >= 0 && $val <= 9) ? ($val * 100 / 9) : -1);
								$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { BatteryLevel => $endpoints{$endpoint}->{properties}->{BatteryLevel} }, []);
							}
						} elsif ($key == 2 and $val >= 0 and $val <= 1) {
							print "Apple dock state changed\n";
							# We map docked state to external power source and undocked state to battery power source
							$endpoints{$endpoint}->{properties}->{PowerSource} = dbus_string($val ? 'external' : 'battery');
							$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { PowerSource => $endpoints{$endpoint}->{properties}->{PowerSource} }, []);
						} else {
							print "Unknown Apple indicator $key\n";
						}
					}
					hsphfpd_socket_write($endpoint, 'OK') or return;
				}
			} elsif ($line eq 'ERROR') {
				print "Received ERROR\n";
				# Some devices send invalid ERROR command in HS role. Do not send anything as it just generates another ERROR
			} else {
				print "Unknown command\n";
				hsphfpd_socket_write($endpoint, 'ERROR') or return;
			}
		} elsif ($profile eq 'hsp_ag') {
			if ($line =~ /^\+VGS=([0-9]+)$/) {
				# AG role describes speaker as local receiving device
				hsphfpd_rx_volume_gain_changed($endpoint, $1);
			} elsif ($line =~ /^\+VGM=([0-9]+)$/) {
				# AG role describes microphone as local transmitting device
				hsphfpd_tx_volume_gain_changed($endpoint, $1);
			} elsif ($line eq 'RING') {
				print "Incoming call event\n";
				$endpoints{$endpoint}->{object}->emit_signal('IncomingCall', 'org.hsphfpd.GatewayEndpoint');
			} elsif ($line =~ /^\+CSRSF:\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+)(?:,\s*([0-9]+)(?:,\s*([0-9]+))?)?/) {
				my $support_battery_level = $4;
				my $support_power_source = $5;
				hsphfpd_csr_supported_features($endpoint, $1, $2, $3, $4, $5, $6, $7);
				hsphfpd_csr_send_battery_level($endpoint) if $support_battery_level;
				hsphfpd_csr_send_power_source($endpoint) if $support_power_source;
			} elsif ($line eq '+CSR=0') {
				hsphfpd_csr_disable($endpoint);
			} elsif ($line =~ /^\+CSR:\s*(\([0-9]+,\s*[0-9]+\)(?:,\s*(?1))?)$/) {
				hsphfpd_csr_indicators_changed($endpoint, $1);
			} elsif ($line =~ /^\+CSRFN:\s*\(6,\s*([0-9]+)\)(?:,\(7,\s*([0-9]+)\))?$/) {
				hsphfpd_csr_select_codec($endpoint, $1, $2);
			} elsif ($line eq '+CSRBATT?') {
				print "Request for battery level\n";
				$endpoints{$endpoint}->{ag_csr_battery_disabled} = 0 if $our_battery_level == -1;
				hsphfpd_csr_send_battery_level($endpoint);
			} elsif ($line eq '+CSRPWR?') {
				print "Request for power source\n";
				$endpoints{$endpoint}->{ag_csr_power_disabled} = 0 if $our_power_source eq 'unknown';
				hsphfpd_csr_send_power_source($endpoint);
			} elsif ($line =~ /^\+CSRSMS:\s*([0-9]+),\s*"([^"]*)",\s*"([^"]*)"$/) {
				# In HSP mode we do not support telephony functions
				print "New SMS with index $1 from number $2 / name $3 has arrived but telephony functions are not supported in HSP profile\n";
			} elsif ($line =~ /^\+CSRGETSMS:\s*(.*)$/) {
				# In HSP mode we do not support telephony functions
				print "Received SMS content '$1' but telephony functions are not supported in HSP profile\n";
			} elsif ($line =~ /^\+CSRTXT:\s*(.*)$/) {
				my $text = $1;
				$endpoints{$endpoint}->{object}->emit_signal('DisplayText', 'org.hsphfpd.GatewayEndpoint', $text);
			} elsif ($line =~ /^\+XAPL=[^\n\r,]*,\s*([0-9]+)$/) {
				my $apple_features = int($1);
				print "Apple features changed event\n";
				my %apple_features;
				foreach (sort { $a <=> $b } keys %apple_features_mask) { $apple_features{$apple_features_mask{$_}} = 1 if $apple_features & int($_); }
				print "Supported Apple features:\n" . (join "\n", sort keys %apple_features) . "\n";
				$endpoints{$endpoint}->{apple_features} = \%apple_features;
				hsphfpd_update_features($endpoint);
			} elsif ($line eq 'OK') {
				print "Received OK\n";
				return 1;
			} elsif ($line eq 'ERROR') {
				print "Received ERROR\n";
				return 0;
			} else {
				print "Unknown command\n";
			}
		} elsif ($profile eq 'hfp_hf') {
			# HFP initial commands (mix of telephony and non-telephony), interaction with Telephony agent at this stage is not allowed, all commands must be processed successfully otherwise HFP connection is dropped
			if ($line =~ /^AT\+BRSF=([0-9]+)$/) {
				my $hf_features = int($1);
				print "HF features changed event\n";
				my %hf_features;
				foreach (sort { $a <=> $b } keys %hf_features_mask) { $hf_features{$hf_features_mask{$_}} = 1 if $hf_features & int($_); }
				print "Supported HF features:\n" . (join "\n", sort keys %hf_features) . "\n";
				$endpoints{$endpoint}->{hf_features} = \%hf_features;
				hsphfpd_update_features($endpoint);
				hsphfpd_rx_volume_control_changed($endpoint, (exists $hf_features{'volume-control'} ? 'remote' : 'none'));
				hsphfpd_tx_volume_control_changed($endpoint, (exists $hf_features{'volume-control'} ? 'remote' : 'none'));
				# We report all defined AG features are supported
				hsphfpd_socket_write($endpoint, "+BRSF: " . int(0b11111111111111)) or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+BAC=([0-9]+(?:,\s*(?1))?)$/) {
				my @hf_codec_ids = map int, split /,\s*/, $1;
				print "HF codecs changed event\n";
				my @hf_codecs = map { exists $hf_codecs_map{$_} ? $hf_codecs_map{$_} : "hf_codec_$_" } @hf_codec_ids;
				print "HF codecs:\n" . (join "\n", @hf_codecs) . "\n";
				$endpoints{$endpoint}->{hf_codecs} = \@hf_codecs;
				hsphfpd_update_codecs($endpoint);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line eq 'AT+CIND=?') {
				print "Request for list of supported AG indicators\n";
				# We report all defined AG indicators are supported
				my $indicators = join ',', map { qq(("$ag_indicators{$_}->{name}",($ag_indicators{$_}->{values}))) } sort { $a <=> $b } keys %ag_indicators;
				hsphfpd_socket_write($endpoint, "+CIND: $indicators") or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line eq 'AT+CIND?') {
				print "Request for values of all AG indicators\n";
				# All indicators except battchg are handled by Telephony agent
				my $values = join ',', map { ($ag_indicators{$_}->{name} eq 'battchg' and $our_battery_level != -1) ? int(5 * $our_battery_level / 100 + 0.5) : 0 } sort { $a <=> $b } keys %ag_indicators;
				hsphfpd_socket_write($endpoint, "+CIND: $values") or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CMER=3,\s*0,\s*0,\s*(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'activating' : 'deactivating') . " reporting of AG indicators\n";
				$endpoints{$endpoint}->{ag_indicators_reporting} = $enable;
				hsphfpd_socket_write($endpoint, 'OK') or return;
				hsphfpd_send_ag_battchg($endpoint) if exists $endpoints{$endpoint}->{ag_indicators}->{$ag_indicator_battchg} and $our_battery_level != -1;
			} elsif ($line eq 'AT+CHLD=?') {
				print "Request for supported call hold and multiparty services\n";
				# We report all defined call hold and multiparty services are supported
				hsphfpd_socket_write($endpoint, '+CHLD: (0,1,1x,2,2x,3,4)') or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CCWA=(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of call waiting notifications\n";
				$endpoints{$endpoint}->{ag_call_waiting_notifications} = $enable;
				# We report that we processed this command
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CMEE=(0|1)$/) {
				my $enable = $1;
				print 'Request for ' . ($enable ? 'enabling' : 'disabling') . " of extended error result codes\n";
				$endpoints{$endpoint}->{ag_extended_error_result_codes} = $enable;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+BIND=([0-9]+(?:,\s*(?1))?)$/) {
				my @hf_indicators_ids = map int, split /,\s*/, $1;
				print "Supported HF indicators changed\n";
				my %hf_indicators = map { $_ => 1 } map { exists $hf_indicators_map{$_} ? $hf_indicators_map{$_} : "hf-indicator-$_" } @hf_indicators_ids;
				print "HF indicators:\n" . (join "\n", sort keys %hf_indicators) . "\n";
				if (exists $endpoints{$endpoint}->{hf_indicators}->{'battery-level'} and not exists $hf_indicators{'battery-level'} and $endpoints{$endpoint}->{properties}->{BatteryLevel}->value() != -1) {
					$endpoints{$endpoint}->{properties}->{BatteryLevel} = dbus_int16(-1);
					$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { BatteryLevel => dbus_int16(-1) }, []);
				}
				$endpoints{$endpoint}->{hf_indicators} = \%hf_indicators;
				hsphfpd_update_features($endpoint);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line eq 'AT+BIND=?') {
				print "Request for list of supported HF indicators\n";
				# We report all defined HF indicators are supported
				my $indicators = join ',', sort { $a <=> $b } keys %hf_indicators_map;
				hsphfpd_socket_write($endpoint, "+BIND: ($indicators)") or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line eq 'AT+BIND?') {
				print "Request for status of HF indicators\n";
				# We report that we want to receive updates of all defined HF indicators
				foreach (sort { $a <=> $b } keys %hf_indicators_map) {
					hsphfpd_socket_write($endpoint, "+BIND: $_,1") or return;
				}
				hsphfpd_socket_write($endpoint, 'OK') or return;

			# HFP non-telephony commands, cannot be processed by Telephony agent
			} elsif ($line eq 'AT+BCC') {
				print "Request for establishment of SCO connection\n";
				hsphfpd_socket_write($endpoint, 'OK') or return;
				return if $endpoints{$endpoint}->{codec_negotiation};
				my $codec = $endpoints{$endpoint}->{selected_codec};
				my ($hf_codec_id) = grep { $hf_codecs_map{$_} eq $codec } keys %hf_codecs_map;
				if (defined $hf_codec_id) {
					hsphfpd_socket_write($endpoint, "+BCS: $hf_codec_id") or return;
				} else {
					# We have already selected non-HF codec
					# Now establish SCO connection
					eval { hsphfpd_connect_audio($endpoint, '', $codec, '') };
				}
			} elsif ($line =~ /^AT\+BCS=([0-9]+)$/) {
				my $hf_codec_id = int($1);
				print "Request for establishment of SCO connection with HF codec id $hf_codec_id\n";
				my $hf_codec = exists $hf_codecs_map{$hf_codec_id} ? $hf_codecs_map{$hf_codec_id} : undef;
				my $adapter = $devices{$endpoints{$endpoint}->{device}}->{adapter};
				my $air_codecs = $adapters{$adapter}->{codecs};
				undef $hf_codec unless defined $hf_codec and exists $air_codecs->{$hf_codec} and grep { grep { $_->{type} eq 'audio' and exists $air_codecs->{$hf_codec}->{$_->{codec}} } @{$_->{agents}} } @applications;
				if (defined $hf_codec) {
					print "Selected HF codec $hf_codec\n";
					$endpoints{$endpoint}->{selected_codec} = $hf_codec;
					$devices{$endpoints{$endpoint}->{device}}->{selected_profile} = $profile;
					hsphfpd_socket_write($endpoint, 'OK') or return;
					return 1 if $endpoints{$endpoint}->{codec_negotiation};
					# Now establish SCO connection
					eval { hsphfpd_connect_audio($endpoint, '', $hf_codec, '') };
				} else {
					print "Requested codec is not supported\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
					return 0 if $endpoints{$endpoint}->{codec_negotiation};
				}
			} elsif ($line =~ /^AT\+BIEV=([0-9]+),\s*([0-9]+)$/) {
				my ($ind, $val) = (int($1), $2);
				print "Update value of HF indicator\n";
				if (not exists $hf_indicators_map{$ind}) {
					print "Unknown indicator $ind\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				} elsif ($hf_indicators_map{$ind} eq 'enhanced-security') {
					print 'Enhanced safety is ' . (($val == 0) ? 'disabled' : ($val == 1) ? 'enabled' : 'unknown') . "\n";
					hsphfpd_socket_write($endpoint, ($val <= 1) ? 'OK' : 'ERROR') or return;
				} elsif ($hf_indicators_map{$ind} eq 'battery-level') {
					my $level = ($val > 100) ? -1 : $val;
					print "Battery level was changed to $level\n";
					$endpoints{$endpoint}->{properties}->{BatteryLevel} = dbus_int16($level);
					$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { BatteryLevel => dbus_int16($level) }, []);
					hsphfpd_socket_write($endpoint, ($level != -1) ? 'OK' : 'ERROR') or return;
				} else {
					print "Unhandled indicator $ind ($hf_indicators_map{$ind})\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line =~ /^AT\+VGS=([0-9]+)$/) {
				my $new_gain = $1;
				hsphfpd_tx_volume_control_changed($endpoint, 'remote');
				hsphfpd_tx_volume_gain_changed($endpoint, $new_gain);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+VGM=([0-9]+)$/) {
				my $new_gain = $1;
				hsphfpd_rx_volume_control_changed($endpoint, 'remote');
				hsphfpd_rx_volume_gain_changed($endpoint, $new_gain);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRSF=([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+)(?:,\s*([0-9]+)(?:,\s*([0-9]+))?)?/) {
				my $response = hsphfpd_csr_supported_features($endpoint, $1, $2, $3, $4, $5, $6, $7);
				hsphfpd_socket_write($endpoint, "+CSRSF: $response") or return;
				hsphfpd_socket_write($endpoint, 'OK') or return;
				hsphfpd_socket_write($endpoint, '+CSRPWR?') if exists $endpoints{$endpoint}->{csr_features}->{'csr-power-source'};
				hsphfpd_socket_write($endpoint, '+CSRBATT?') if exists $endpoints{$endpoint}->{csr_features}->{'csr-battery-level'};
			} elsif ($line eq 'AT+CSR=0') {
				hsphfpd_csr_disable($endpoint);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSR=(\([0-9]+,\s*[0-9]+\)(?:,\s*(?1))?)$/) {
				hsphfpd_csr_indicators_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRFN=\(6,\s*([0-9]+)\)(?:,\(7,\s*([0-9]+)\))?$/) {
				hsphfpd_csr_select_codec($endpoint, $1, $2);
			} elsif ($line =~ /^AT\+CSRBATT=([0-9])$/) {
				hsphfpd_csr_battery_level_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+CSRPWR=([1-2])$/) {
				hsphfpd_csr_power_source_changed($endpoint, $1);
				hsphfpd_socket_write($endpoint, 'OK') or return;
			} elsif ($line =~ /^AT\+XAPL=[0-9A-Fa-f]+-[0-9A-Fa-f]+-[^\n\r,]+,\s*([0-9]+)$/) {
				my $apple_features = int($1);
				print "Apple features changed event\n";
				my %apple_features;
				foreach (sort { $a <=> $b } keys %apple_features_mask) { $apple_features{$apple_features_mask{$_}} = 1 if $apple_features & int($_); }
				print "Supported Apple features:\n" . (join "\n", sort keys %apple_features) . "\n";
				$endpoints{$endpoint}->{apple_features} = \%apple_features;
				hsphfpd_update_features($endpoint);
				hsphfpd_socket_write($endpoint, "+XAPL=iPhone," . int(0b11110)) or return;
			} elsif ($line =~ /^AT\+IPHONEACCEV=([0-9]+)(,\s*[0-9]+,\s*[0-9]+(?2)?)?$/) {
				my ($count, $indicators) = ($1, $2);
				print "Apple indicators changed event\n";
				my @indicators = ($indicators =~ /([0-9]+,\s*[0-9]+)/g);
				if (scalar @indicators != $count) {
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				} else {
					foreach (@indicators) {
						my ($key, $val) = split /,\s*/, $_;
						if ($key == 1 and $val >=0 and $val <= 9) {
							print "Apple battery level changed\n";
							# Apple battery level is only in range 0-9 but HF battery level is range 0-100, so prefer usage of HF
							if (not exists $endpoints{$endpoint}->{hf_indicators}->{'battery-level'}) {
								$endpoints{$endpoint}->{properties}->{BatteryLevel} = dbus_int16(($val >= 0 && $val <= 9) ? ($val * 100 / 9) : -1);
								$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { BatteryLevel => $endpoints{$endpoint}->{properties}->{BatteryLevel} }, []);
							}
						} elsif ($key == 2 and $val >= 0 and $val <= 1) {
							print "Apple dock state changed\n";
							# We map docked state to external power source and undocked state to battery power source
							$endpoints{$endpoint}->{properties}->{PowerSource} = dbus_string($val ? 'external' : 'battery');
							$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { PowerSource => $endpoints{$endpoint}->{properties}->{PowerSource} }, []);
						} else {
							print "Unknown Apple indicator $key\n";
						}
					}
					hsphfpd_socket_write($endpoint, 'OK') or return;
				}

			# HFP telephony commands which needs to be handled by hfphfpd and so cannot be forwarded to Telephony agent
			} elsif ($line =~ /^AT\+BIA=((?:0|1|)(?:,\s*(?1))?)$/) {
				my @inds = split /,\s*/, $1;
				print "Request for activating or deactivating individual AG indicators\n";
				my $error;
				my $battchg_activated;
				for my $ind (0..$#inds) {
					if (not exists $ag_indicators{$ind+1}) {
						print 'AG indicator with id ' . ($ind+1) . " does not exist\n";
						$error = 1;
					} elsif ($inds[$ind] eq '1' and not exists $endpoints{$endpoint}->{ag_indicators}->{$ind+1}) {
						print 'Activating AG indicator ' . $ag_indicators{$ind+1}->{name} . "\n";
						$endpoints{$endpoint}->{ag_indicators}->{$ind+1} = 1;
						$battchg_activated = 1 if $ind+1 == $ag_indicator_battchg;
					} elsif ($inds[$ind] eq '0' and exists $endpoints{$endpoint}->{ag_indicators}->{$ind+1}) {
						print 'Deactivating AG indicator ' . $ag_indicators{$ind+1}->{name} . "\n";
						delete $endpoints{$endpoint}->{ag_indicators}->{$ind+1};
					}
				}
				hsphfpd_socket_write($endpoint, $error ? 'ERROR' : 'OK') or return;
				hsphfpd_send_ag_battchg($endpoint) if $battchg_activated and $our_battery_level != -1;
				if (exists $endpoints{$endpoint}->{telephony}) {
					my @inds_for_telephony = @inds;
					# All indicators except battchg are handled by Telephony agent
					$inds_for_telephony[$ag_indicator_battchg-1] = 0 if $ag_indicator_battchg-1 <= $#inds_for_telephony;
					hsphfpd_telephony_write($endpoint, 'AT+BIA=' . join ',', @inds_for_telephony) and hsphfpd_telephony_wait_for_ok_error($endpoint);
				}

			# HFP telephony commands which are bluetooth specific
			} elsif ($line eq 'AT+BINP=1') {
				print "Request for phone number corresponding to the last voice tag\n";
				hsphfpd_button_pressed($endpoint);
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line eq 'AT+BLDN') {
				print "Request for calling last number\n";
				hsphfpd_button_pressed($endpoint);
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line =~ /^AT\+BVRA=([0-2])$/) {
				print "Request for enabling/disabling of voice recognition function\n";
				hsphfpd_button_pressed($endpoint);
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line eq 'AT+NREC=0') {
				print "Request for disabling of noise reduction and echo canceling\n";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					# ERROR means that NR and EC are unsupported
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line eq 'AT+BTRH?') {
				print "Request for state of Response and Hold feature\n";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					# Response without +BTRH: lines means that there is no held call
					hsphfpd_socket_write($endpoint, 'OK') or return;
				}
			} elsif ($line =~ /^AT\+BTRH=([0-2])$/) {
				print "Request for chaning state of Response and Hold feature\n";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line =~ /^AT\+CSRGETSMS=([0-9]+)$/) {
				print "Request for content of SMS with index $1\n";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			} elsif ($line eq 'AT+APLSIRI?') {
				print "Request for Siri status, but telephony agent is not connected\n";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					# 2 = Siri is available but not enabled
					hsphfpd_socket_write($endpoint, '+APLSIRI: 2') or return;
				}
			} elsif ($line =~ /^AT\+APLEFM=(0x[0-9a-fA-F]+|[0-9]+)$/) {
				print "Siri Eyes Free mode changed";
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					# $1 = 0x00 or 0 means Siri Eyes Free mode is disabled
					# $1 = 0x01 or 1 means Siri Eyes Free mode is enabled
					# OK is the only allowed response
					hsphfpd_socket_write($endpoint, 'OK') or return;
				}

			# HFP telephony command which are standard AT but we should handle it for button press event
			} elsif ($line eq 'ATA') {
				print "Request for accepting incoming call\n";
				hsphfpd_button_pressed($endpoint);
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
					# Send AG indicators that there is no call
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_call,0") or return;
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_callsetup,0") or return;
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_call_setup,0") or return;
				}
			} elsif ($line eq 'AT+CHUP') {
				print "Request for terminating active or rejecting incoming call\n";
				hsphfpd_button_pressed($endpoint);
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} else {
					print "Telephony agent is not connected\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
					# Send AG indicators that there is no call
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_call,0") or return;
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_callsetup,0") or return;
					hsphfpd_socket_write($endpoint, "+CIEV: $ag_indicator_call_setup,0") or return;
				}

			# Other commands, forward them to Telephony agent
			} else {
				if (exists $endpoints{$endpoint}->{telephony}) {
					print "Other command, forwarding to telephony agent\n";
					hsphfpd_telephony_write($endpoint, $origline, 1);
				} elsif ($line eq 'ERROR') {
					print "Received ERROR\n";
					# Some devices send invalid ERROR command in HF role. Do not send anything as it just generates another ERROR
				} else {
					print "Unknown command\n";
					hsphfpd_socket_write($endpoint, 'ERROR') or return;
				}
			}
		} elsif ($profile eq 'hfp_ag') {
			# TODO: implement HFP AG role
		}
	}
	return;
}

sub hsphfpd_sock_exception {
	my ($endpoint) = @_;
	print "Socket exception: endpoint=$endpoint\n";
	hsphfpd_disconnect_endpoint($endpoint);
}

sub hsphfpd_connect_endpoint {
	my ($endpoint, $socket) = @_;
	print "Opening connection for endpoint $endpoint\n";
	$endpoints{$endpoint}->{socket} = $socket;
	$reactor->add_read(fileno $socket, sub { hsphfpd_socket_ready_read($endpoint) });
	$reactor->add_exception(fileno $socket, sub { hsphfpd_sock_exception($endpoint) });
	$endpoints{$endpoint}->{properties}->{Connected} = dbus_boolean(1);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { Connected => dbus_boolean(1) }, []);
	my $profile = $endpoints{$endpoint}->{profile};

	if ($profile eq 'hfp_hf') {
		my %hf_features;
		foreach (sort { $a <=> $b } keys %hf_profile_features_mask) { $hf_features{$hf_profile_features_mask{$_}} = 1 if $endpoints{$endpoint}->{profile_features} & int($_); }
		$endpoints{$endpoint}->{hfp_wide_band_speech} = exists $hf_features{'wide-band-speech'};
		print "Supported HF profile features:\n" . (join "\n", sort keys %hf_features) . "\n";
		$endpoints{$endpoint}->{hf_features} = \%hf_features;
		hsphfpd_update_features($endpoint);
		# When volume-control feature is present, expects that it represents both RX and TX
		hsphfpd_rx_volume_control_changed($endpoint, 'remote') if exists $endpoints{$endpoint}->{hf_features}->{'volume-control'};
		hsphfpd_tx_volume_control_changed($endpoint, 'remote') if exists $endpoints{$endpoint}->{hf_features}->{'volume-control'};
	} elsif ($profile eq 'hfp_ag') {
		my %ag_features;
		foreach (sort { $a <=> $b } keys %ag_profile_features_mask) { $ag_features{$ag_profile_features_mask{$_}} = 1 if $endpoints{$endpoint}->{profile_features} & int($_); }
		$endpoints{$endpoint}->{hfp_wide_band_speech} = exists $ag_features{'wide-band-speech'};
		print "Supported AG profile features:\n" . (join "\n", sort keys %ag_features) . "\n";
		$endpoints{$endpoint}->{ag_features} = \%ag_features;
		hsphfpd_update_features($endpoint);
	} elsif ($profile eq 'hsp_hs') {
		# NOTE: bluez since 5.55 sets first bit to value from SDP attribute 0x0302 "Remote audio volume control"
		$endpoints{$endpoint}->{hs_volume_control} = $endpoints{$endpoint}->{profile_features} & int(0b1);
		print "Supported HS profile features:\n" . ($endpoints{$endpoint}->{hs_volume_control} ? 'volume-control' : '') . "\n";
		hsphfpd_update_features($endpoint);
		# When volume-control feature is present, expects that it represents both RX and TX
		hsphfpd_rx_volume_control_changed($endpoint, 'remote') if $endpoints{$endpoint}->{hs_volume_control};
		hsphfpd_tx_volume_control_changed($endpoint, 'remote') if $endpoints{$endpoint}->{hs_volume_control};
	}

	if ($profile eq 'hsp_ag') {
		# AG role describes speaker as local receiving device
		hsphfpd_socket_write($endpoint, "AT+VGS=" . $endpoints{$endpoint}->{rx_volume_gain}) or throw_dbus_error('org.bluez.Error.Canceled', 'Canceled');
		if (not hsphfpd_socket_wait_for_ok_error($endpoint)) {
			hsphfpd_rx_volume_control_changed($endpoint, 'none');
		}
		# AG role describes microphone as local transmitting device
		hsphfpd_socket_write($endpoint, "AT+VGM=" . $endpoints{$endpoint}->{tx_volume_gain}) or throw_dbus_error('org.bluez.Error.Canceled', 'Canceled');
		if (not hsphfpd_socket_wait_for_ok_error($endpoint)) {
			hsphfpd_tx_volume_control_changed($endpoint, 'none');
		}
		# TODO: send AT+XAPL=
		# In HSP mode we do not support telephony functions, so caller_name and sms_ind is not announced
		hsphfpd_socket_write($endpoint, "AT+CSRSF=0,1,0,1,1,7,3") or throw_dbus_error('org.bluez.Error.Canceled', 'Canceled');
		hsphfpd_socket_wait_for_ok_error($endpoint);
	} elsif ($profile eq 'hfp_ag') {
		# TODO: implement HFP AG role
		# send: AT+BRSF= if profile version >= 1.00
		# receive: +BRSF:
		# receive: OK
		# send: AT+BAC= if device supports codec selection
		# receive: OK
		# send: AT+CIND=?
		# receive: +CIND:
		# receive: OK
		# send: AT+CIND?
		# receive: +CIND:
		# receive: OK
		# send: AT+CMER
		# receive: OK
		# send: AT+CHLD=?
		# recive: +CHLD:
		# receive: OK
		# send: AT+BIND=
		# receive: +BIND:
		# receive: OK
		# send: AT+BIND?
		# receive: +BIND:
		# receive: +BIND:
		# ...
		# receive: OK
		# send: AT+XAPL=0000-0000-0000,30
		# receive: +XAPL=|ERROR or nothing/timeout
		# send: AT+CSRSF=1,1,1,1,1,7,3
		# receive: +CSRSF:|ERROR or nothing/timeout
		# receive: OK|ERROR or nothing/timeout
	} else {
		my $uinput;
		do {{ # double {{ so keyword "last" would work
			my $name = $endpoints{$endpoint}->{properties}->{Name}->value() . ' (' . (($profile =~ /^hsp_/) ? 'HSP' : 'HFP') . ')';
			my ($vendor, $product, $version) = map { hex $_ } $endpoints{$endpoint}->{modalias} =~ /^[^:]*:v([0-9a-fA-F]*)p([0-9a-fA-F]*)d([0-9a-fA-F]*)$/;
			$vendor //= $product //= $version //= 0;
			print "Creating uinput device for endpoint $endpoint: $name\n";
			# Opening uinput device may fail if we are not running under root, so do not die
			open $uinput, '>', '/dev/uinput' or $!{ENOENT} && open $uinput, '>', '/dev/input/uinput' or $!{ENOENT} && open $uinput, '>', '/dev/misc/uinput' or do { print "Cannot open uinput device: $!\n"; last };
			# UI_SET_EVBIT => 1074025828, EV_KEY => 1
			ioctl $uinput, 1074025828, 1 or do { print "Cannot call ioctl UI_SET_EVBIT EV_KEY on uinput device: $!\n"; last };
			# UI_SET_EVBIT => 1074025828, EV_SYN => 0
			ioctl $uinput, 1074025828, 0 or do { print "Cannot call ioctl UI_SET_EVBIT EV_SYN on uinput device: $!\n"; last };
			# UI_SET_KEYBIT => 1074025829, KEY_PHONE => 169
			ioctl $uinput, 1074025829, 169 or do { print "Cannot call ioctl UI_SET_KEYBIT KEY_PHONE on uinput device: $!\n"; last };
			# UI_SET_PHYS => 1074287980
			ioctl $uinput, 1074287980, pack 'Z*', lc $endpoints{$endpoint}->{properties}->{LocalAddress}->value() or print "Cannot call ioctl UI_SET_PHYS on uinput device: $!\n";
			# UI_SET_UNIQ => 1074287983
			ioctl $uinput, 1074287983, pack 'Z*', lc $endpoints{$endpoint}->{properties}->{RemoteAddress}->value() or print "Cannot call ioctl UI_SET_UNIQ on uinput device: $!\n";
			# struct uinput_user_dev { char name[UINPUT_MAX_NAME_SIZE]; struct input_id id; uint32_t ff_effects_max; int32_t absmax[ABS_CNT]; int32_t absmin[ABS_CNT]; int32_t absfuzz[ABS_CNT]; int32_t absflat[ABS_CNT]; }, struct input_id { uint16_t bustype; uint16_t vendor; uint16_t product; uint16_t version; }, BUS_BLUETOOTH => 5
			syswrite $uinput, pack 'a[80](S)4L((l)[64])4', $name, 5, $vendor, $product, $version, 0, (((0) x 64) x 4) or do { print "Cannot write device name to uinput device: $!\n"; last };
			# UI_DEV_CREATE => 21761
			ioctl $uinput, 21761, 0 or do { print "Cannot call ioctl UI_DEV_CREATE on uinput device: $!\n"; last };
			$endpoints{$endpoint}->{uinput} = $uinput;
		}} while 0;
		if (not exists $endpoints{$endpoint}->{uinput} and defined fileno $uinput and fileno $uinput >= 0) {
			# UI_DEV_DESTROY => 21762
			ioctl $uinput, 21762, 0;
			close $uinput;
		}
	}

	if ($profile =~ /^hfp_/) {
		my $timer_id; # postpone connecting telephony agent for 3s
		$timer_id = $reactor->add_timeout(3000, sub {
			hsphfpd_connect_telephony($endpoint);
			$reactor->remove_timeout($timer_id);
		});
	}

	$devices{$endpoints{$endpoint}->{device}}->{selected_profile} = $profile;
}

sub hsphfpd_disconnect_endpoint {
	my ($endpoint) = @_;
	my $socket = delete $endpoints{$endpoint}->{socket};
	return unless defined $socket;
	hsphfpd_disconnect_audio($endpoints{$endpoint}->{audio}) if exists $endpoints{$endpoint}->{audio};
	hsphfpd_disconnect_telephony($endpoint) if exists $endpoints{$endpoint}->{telephony};
	if (exists $endpoints{$endpoint}->{uinput}) {
		print "Destroying uinput device for endpoint $endpoint\n";
		# UI_DEV_DESTROY => 21762
		ioctl $endpoints{$endpoint}->{uinput}, 21762, 0;
		close $endpoints{$endpoint}->{uinput};
		delete $endpoints{$endpoint}->{uinput};
	}
	print "Closing connection for endpoint $endpoint\n";
	$reactor->remove_read(fileno $socket);
	$reactor->remove_exception(fileno $socket);
	shutdown $socket, 2;
	close $socket;
	$endpoints{$endpoint}->{properties}->{Connected} = dbus_boolean(0);
	$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { Connected => dbus_boolean(0) }, []);
}


sub bluez_new_connection {
	my ($profile, $caller, $device, $fd, $properties) = @_;
	throw_dbus_error('org.bluez.Error.Rejected', qq(Cannot open supplied file descriptor "$fd": Bad file descriptor)) unless $fd =~ /^[0-9]+$/;
	# After successful open() call, $socket owns $fd and close($socket) would close also $fd
	open my $socket, '+<&=', $fd or throw_dbus_error('org.bluez.Error.Canceled', qq(Cannot open supplied file descriptor "$fd": $!));
	select((select($socket), $| = 1)[0]); # enable autoflush
	throw_dbus_error('org.bluez.Error.Rejected', qq(Caller "$caller" does not own "org.bluez" service)) if $bluez_service->get_owner_name() ne $caller;
	throw_dbus_error('org.bluez.Error.Rejected', qq(Invalid device object path)) unless defined $device and $device =~ m{^/};
	throw_dbus_error('org.bluez.Error.Canceled', qq(Device "$device" does not support profile "$profile")) unless exists $devices{$device}->{profiles}->{$profile};
	my $endpoint = $devices{$device}->{profiles}->{$profile};
	throw_dbus_error('org.bluez.Error.Canceled', qq(Device "$device" has already open connection for profile "$profile")) if exists $endpoints{$endpoint}->{socket};
	throw_dbus_error('org.bluez.Error.Rejected', qq(Invalid properties structure)) unless ref $properties eq 'HASH';
	my $version = exists $properties->{Version} ? $properties->{Version} : '';
	$version = ($version =~ /^[0-9]+$/) ? (sprintf "%x.%x", ($version >> 8), ($version & 0xFF)) : '';
	my $features = exists $properties->{Features} ? $properties->{Features} : '';
	$features = ($features =~ /^[0-9]+$/) ? int($features) : ($profile eq 'hfp_ag') ? 0b001001 : 0;
	print "New connection: endpoint=$endpoint profile=$profile device=$device fd=$fd version=$version features=$features\n";
	$endpoints{$endpoint}->{profile_features} = $features;
	if ($endpoints{$endpoint}->{properties}->{Version}->value() ne $version) {
		$endpoints{$endpoint}->{properties}->{Version} = dbus_string($version);
		$endpoints{$endpoint}->{object}->emit_signal('PropertiesChanged', 'org.hsphfpd.Endpoint', { Version => dbus_string($version) }, []);
	}
	hsphfpd_connect_endpoint($endpoint, $socket);
}

sub bluez_disconnect_connection {
	my ($profile, $caller, $device) = @_;
	throw_dbus_error('org.bluez.Error.Rejected', qq(Caller "$caller" does not own "org.bluez" service)) if $bluez_service->get_owner_name() ne $caller;
	throw_dbus_error('org.bluez.Error.Rejected', qq(Invalid device object path)) unless defined $device and $device =~ m{^/};
	throw_dbus_error('org.bluez.Error.Rejected', qq(Device "$device" does not support profile "$profile")) unless exists $devices{$device}->{profiles}->{$profile};
	my $endpoint = $devices{$device}->{profiles}->{$profile};
	throw_dbus_error('org.bluez.Error.Rejected', qq(Device "$device" does not have open connection for profile "$profile")) unless exists $endpoints{$endpoint}->{socket};
	print "Disconnect connection: endpoint=$endpoint profile=$profile device=$device\n";
	hsphfpd_disconnect_endpoint($endpoint);
}

sub bluez_release_profile {
	my ($profile, $caller) = @_;
	throw_dbus_error('org.bluez.Error.Rejected', qq(Caller "$caller" does not own "org.bluez" service)) if defined $caller and $bluez_service->get_owner_name() ne $caller;
	if (exists $profiles{$profile}) {
		hsphfpd_disconnect_endpoint($_) foreach sort grep { $endpoints{$_}->{profile} eq $profile } keys %endpoints;
		delete $profiles{$profile};
		print "Released profile $profile\n";
	}
}

sub bluez_register_profile {
	my ($profile, $uuid, $properties) = @_;
	eval {
		$bluez_profile_manager->RegisterProfile(dbus_object_path("/org/bluez/profile/$profile"), dbus_string($uuid), $properties);
		1;
	} and do {
		print "Registered profile $profile\n";
		$profiles{$profile} = 1;
	} or do {
		print "Registering profile $profile failed: $@";
	} unless exists $profiles{$profile};
}

sub bluez_release_profiles {
	bluez_release_profile($_) foreach sort keys %profiles;
}

sub bluez_register_profiles {
	# Service Record definition for Headset role of HSP 1.2 profile with Erratum 3507
	# Attribute 0x0302 is Remote Audio Volume Control, default value is false
	my $hsp_ag_name = 'Headset unit';
	my $hsp_ag_version = '0x0102';
	my $hsp_ag_channel = '0x06';
	my $hsp_ag_record = <<"EOD";
<?xml version="1.0" encoding="UTF-8" ?>
<record>
	<attribute id="0x0001">
		<sequence>
			<uuid value="0x1108" />
			<uuid value="0x1131" />
			<uuid value="0x1203" />
		</sequence>
	</attribute>
	<attribute id="0x0004">
		<sequence>
			<sequence>
				<uuid value="0x0100" />
			</sequence>
			<sequence>
				<uuid value="0x0003" />
				<uint8 value="$hsp_ag_channel" />
			</sequence>
		</sequence>
	</attribute>
	<attribute id="0x0005">
		<sequence>
			<uuid value="0x1002" />
		</sequence>
	</attribute>
	<attribute id="0x0009">
		<sequence>
			<sequence>
				<uuid value="0x1108" />
				<uint16 value="$hsp_ag_version" />
			</sequence>
		</sequence>
	</attribute>
	<attribute id="0x0100">
		<text value="$hsp_ag_name" />
	</attribute>
	<attribute id="0x0302">
		<boolean value="true" />
	</attribute>
</record>
EOD

	bluez_register_profile('hfp_hf', '0000111f-0000-1000-8000-00805f9b34fb', { Version => dbus_uint16(0x0108), Features => dbus_uint16(0b11111111) }); # bluez prior to version 5.50 sets version in SDP record for HFP_AG to 1.5
	bluez_register_profile('hsp_hs', '00001112-0000-1000-8000-00805f9b34fb', { Version => dbus_uint16(0x0102) }); # bluez prior to version 5.26 does not set version in SDP record for HSP_AG profile
	# TODO: implement HFP AG role
	#bluez_register_profile('hfp_ag', '0000111e-0000-1000-8000-00805f9b34fb', { Version => dbus_uint16(0x0108), Features => dbus_uint16(0b11111111) }); # bluez prior to version 5.50 sets version in SDP record for HFP_HF to 1.5
	bluez_register_profile('hsp_ag', '00001108-0000-1000-8000-00805f9b34fb', { Name => dbus_string($hsp_ag_name), Version => dbus_uint16(hex($hsp_ag_version)), Features => dbus_uint16(0b1), AutoConnect => dbus_boolean(1), Channel => dbus_uint16(hex($hsp_ag_channel)), ServiceRecord => dbus_string($hsp_ag_record) }); # bluez prior to version 5.55 does not have SDP record for HSP_HS profile
}

sub bluez_obj_weight {
	my ($obj) = @_;
	return 5 unless ref $obj eq 'HASH';
	return 1 if exists $obj->{'org.bluez.ProfileManager1'};
	return 2 if exists $obj->{'org.bluez.Adapter1'};
	return 3 if exists $obj->{'org.bluez.Device1'};
	return 4;
}

sub bluez_enumerate_objects {
	my $bluez_objects = eval { $bluez_object_manager->GetManagedObjects() };
	return unless defined $bluez_objects;
	bluez_interfaces_added($_, $bluez_objects->{$_}) foreach sort { bluez_obj_weight($bluez_objects->{$a}) <=> bluez_obj_weight($bluez_objects->{$b}) or $a cmp $b } keys %{$bluez_objects};
}

sub bluez_interfaces_added {
	my ($path, $interfaces) = @_;
	return unless defined $path and defined $interfaces;
	return unless ref $path eq '' and ref $interfaces eq 'HASH';
	if (exists $interfaces->{'org.bluez.ProfileManager1'} and $path eq '/org/bluez') {{
		bluez_register_profiles();
		print "added: profile_manager=$path\n";
	}}
	if (exists $interfaces->{'org.bluez.Adapter1'}) {{
		my $adapter = $path;
		last if exists $adapters{$adapter};
		my $adapter_props = $interfaces->{'org.bluez.Adapter1'};
		last unless ref $adapter_props eq 'HASH' and exists $adapter_props->{Address};
		my $address = $adapter_props->{Address};
		last unless ref $address eq '';
		my %codecs;
		if ($kernel_anycodec_support) {
			# TODO: use HCI commands to checks which codecs are really supported by adapter
			# But it needs root privileges and anycodec support is in implemented in kernel yet
			$codecs{CVSD}->{$_} = $codecs{alaw}->{$_} = $codecs{ulaw}->{$_} = 1 foreach qw(alaw ulaw PCM_s16le_8kHz PCM_u16le_8kHz PCM_s8le_8kHz PCM_u8le_8kHz);
			$codecs{$_}->{$_} = 1 foreach qw(AuriStream_2bit_8kHz AuriStream_2bit_16kHz AuriStream_4bit_8kHz AuriStream_4bit_16kHz mSBC);
		} elsif ($kernel_msbc_support) {
			if ($adapter =~ /hci([0-9]+)$/) {
				# Check that adapter supports eSCO link and transparent air codec
				my $hci_id = $1;
				# PF_BLUETOOTH => 31, SOCK_RAW => 3, BTPROTO_HCI => 1
				if (socket my $hci_socket, 31, 3, 1) {
					# AF_BLUETOOTH => 31, struct sockaddr_hci { sa_family_t hci_family; unsigned short hci_dev; unsigned short hci_channel; }, sa_family_t = uint16_t
					if (bind $hci_socket, pack 'SS!S!', 31, $hci_id, 0) {
						my $dev_info = "\0" x 92;
						# HCIGETDEVINFO => 2147764435;
						if (ioctl $hci_socket, 2147764435, $dev_info) {
							my @features = unpack 'C8', substr $dev_info, 21, 8;
							my $esco_link = ($features[3] & (1 << 7));
							my $transparent_air_coding = ($features[2] & (1 << 3));
							$codecs{mSBC}->{mSBC} = 1 if $esco_link and $transparent_air_coding;
						}
					}
					close $hci_socket;
				}
			}
		}
		$codecs{CVSD}->{PCM_s16le_8kHz} = 1; # This default codec should be always supported by adapter
		print "Supported codecs combination for adapter $adapter:\n";
		print "Air codec $_ with agent codecs: " . (join ', ', sort keys %{$codecs{$_}}) . "\n" foreach sort keys %codecs;
		$adapters{$adapter} = { address => $address, devices => {}, codecs => \%codecs };
		print "added: adapter=$adapter address=$address\n";
	}}
	if (exists $interfaces->{'org.bluez.Device1'}) {{
		my $device = $path;
		my $device_props = $interfaces->{'org.bluez.Device1'};
		last unless ref $device_props eq 'HASH';
		my $address = $device_props->{Address};
		last unless ref $address eq '';
		my $adapter = $device_props->{Adapter};
		last unless ref $adapter eq '';
		last unless exists $adapters{$adapter};
		my $name = $device_props->{Name};
		$name = '' unless ref $name eq '';
		my $modalias = $device_props->{Modalias};
		$modalias = '' unless defined $modalias and ref $modalias eq '';
		last unless exists $device_props->{'UUIDs'};
		my $uuids = $device_props->{UUIDs};
		last unless ref $uuids eq 'ARRAY';
		foreach (@{$uuids}) {
			my ($profile, $profile_name, $role_name, $class);
			my $init_volume_control = 'none';
			my $ag_indicators;
			if ($_ eq '00001108-0000-1000-8000-00805f9b34fb' or $_ eq '00001131-0000-1000-8000-00805f9b34fb') {
				$profile = 'hsp_hs';
				$profile_name = 'headset';
				$role_name = 'client';
				$class = 'main::HSPClientEndpoint';
			} elsif ($_ eq '00001112-0000-1000-8000-00805f9b34fb') {
				$profile = 'hsp_ag';
				$profile_name = 'headset';
				$role_name = 'gateway';
				$class = 'main::HSPGatewayEndpoint';
				$init_volume_control = 'local';
			} elsif ($_ eq '0000111e-0000-1000-8000-00805f9b34fb') {
				$profile = 'hfp_hf';
				$profile_name = 'handsfree';
				$role_name = 'client';
				$class = 'main::HFPClientEndpoint';
				$ag_indicators = { map { $_ => 1 } keys %ag_indicators };
			} elsif ($_ eq '0000111f-0000-1000-8000-00805f9b34fb') {
				$profile = 'hfp_ag';
				$profile_name = 'handsfree';
				$role_name = 'gateway';
				$class = 'main::HFPGatewayEndpoint';
				$init_volume_control = 'local';
			} else {
				next;
			}
			my $endpoint_suffix = "org/hsphfpd" . (($device =~ m{^/org/bluez(/.*)$}) ? $1 : $device) . "/$profile";
			my $endpoint = $hsphfpd_manager->get_object_path();
			$endpoint =~ s{^/}{} if $endpoint ne '/';
			$endpoint .= $endpoint_suffix;
			next if exists $endpoints{$endpoint};
			my $adapter_address = $adapters{$adapter}->{address};
			$adapters{$adapter}->{devices}->{$device} = 1;
			$devices{$device}->{adapter} = $adapter;
			$devices{$device}->{profiles}->{$profile} = $endpoint;
			# TODO: load codecs, gains, profile, version, last codec and features from local cache
			$endpoints{$endpoint} = { device => $device, modalias => $modalias, profile => $profile, ag_indicators => $ag_indicators // {}, rx_volume_control => $init_volume_control, tx_volume_control => $init_volume_control, ag_indicators_reporting => 0, hf_features => {}, ag_features => {}, csr_features => {}, apple_features => {}, hf_indicators => {}, hf_codecs => [], csr_codecs => [], rx_volume_gain => 8, tx_volume_gain => 8, selected_codec => 'CVSD', codecs => { CVSD => 1 } };
			$endpoints{$endpoint}->{properties} = { Name => dbus_string($name), LocalAddress => dbus_string($adapter_address), RemoteAddress => dbus_string($address), Connected => dbus_boolean(0), AudioConnected => dbus_boolean(0), TelephonyConnected => dbus_boolean(0), Profile => dbus_string($profile_name), Version => dbus_string(''), Role => dbus_string($role_name), PowerSource => dbus_string('unknown'), BatteryLevel => dbus_int16(-1), Features => dbus_array([]), AudioCodecs => dbus_array([ dbus_string('CVSD') ]) };
			$endpoints{$endpoint}->{object} = $class->new($hsphfpd_manager, $endpoint_suffix);
			$hsphfpd_manager->emit_signal('InterfacesAdded', $endpoint, { 'org.hsphfpd.Endpoint' => $endpoints{$endpoint}->{properties} });
			print "added: device=$device adapter=$adapter endpoint=$endpoint local_address=$adapter_address remote_address=$address profile=$profile\n";
		}
	}}
}

sub bluez_interfaces_removed {
	my ($path, $interfaces) = @_;
	return unless defined $path and defined $interfaces;
	return unless ref $path eq '' and ref $interfaces eq 'ARRAY';
	foreach (@{$interfaces}) {
		next unless ref $_ eq '';
		if ($_ eq 'org.bluez.ProfileManager1' and $path eq '/org/bluez') {
			bluez_release_profiles();
			print "removed: profile_manager=$path\n";
		} elsif ($_ eq 'org.bluez.Adapter1' and exists $adapters{$path}) {
			my $adapter = $path;
			bluez_interfaces_removed($_, [ 'org.bluez.Device1' ]) foreach sort keys %{$adapters{$adapter}->{devices}};
			delete $adapters{$adapter};
			print "removed: adapter=$adapter\n";
		} elsif ($_ eq 'org.bluez.Device1' and exists $devices{$path}) {
			my $device = $path;
			my $adapter = $devices{$device}->{adapter};
			foreach (sort values %{$devices{$device}->{profiles}}) {
				hsphfpd_disconnect_endpoint($_);
				$endpoints{$_}->{object}->disconnect();
				$hsphfpd_manager->emit_signal('InterfacesRemoved', $_, [ 'org.hsphfpd.Endpoint' ]);
				delete $endpoints{$_};
			}
			delete $devices{$device};
			delete $adapters{$adapter}->{devices}->{$device};
			print "removed: device=$device\n";
		}
	}
}

{
	package main::Manager;
	use parent 'Net::DBus::Object';
	use Net::DBus::Exporter 'org.hsphfpd.ApplicationManager';
	BEGIN {
		dbus_method('RegisterApplication', [ 'caller', 'objectpath', ], [], { strict_exceptions => 1, param_names => [ 'application' ] });
		dbus_method('UnregisterApplication', [ 'caller', 'objectpath' ], [], { strict_exceptions => 1, param_names => [ 'application' ] });
		dbus_method('GetManagedObjects', [], [ [ 'dict', 'objectpath', [ 'dict', 'string', [ 'dict', 'string', [ 'variant' ] ] ] ] ], 'org.freedesktop.DBus.ObjectManager', { strict_exceptions => 1, return_names => [ 'object_paths_interfaces_and_properties' ] });
		dbus_signal('InterfacesAdded', [ 'objectpath', [ 'dict', 'string', [ 'dict', 'string', [ 'variant' ] ] ] ], 'org.freedesktop.DBus.ObjectManager', { param_names => [ 'object_path', 'interfaces_and_properties' ] });
		dbus_signal('InterfacesRemoved', [ 'objectpath', [ 'array', 'string' ] ], 'org.freedesktop.DBus.ObjectManager', { param_names => [ 'object_path', 'interfaces' ] });
	}
}
sub main::Manager::RegisterApplication { shift; hsphfpd_register_application(@_) }
sub main::Manager::UnregisterApplication { shift; hsphfpd_unregister_application(@_) }
sub main::Manager::GetManagedObjects { hsphfpd_get_endpoints() }

{
	package main::Endpoint;
	use parent 'Net::DBus::Object';
	use Net::DBus::Exporter 'org.hsphfpd.Endpoint';
	BEGIN {
		dbus_method('ConnectAudio', [ 'caller', 'string', 'string' ], [ 'objectpath', 'string', 'objectpath' ], { strict_exceptions => 1, param_names => [ 'air_codec', 'agent_codec' ] });
		dbus_property('Name', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('RemoteAddress', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('LocalAddress', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('Connected', 'bool', 'read', { strict_exceptions => 1 });
		dbus_property('AudioConnected', 'bool', 'read', { strict_exceptions => 1 });
		dbus_property('TelephonyConnected', 'bool', 'read', { strict_exceptions => 1 });
		dbus_property('Profile', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('Version', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('Role', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('PowerSource', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('BatteryLevel', 'int16', 'read', { strict_exceptions => 1 });
		dbus_property('Features', [ 'array', 'string' ], 'read', { strict_exceptions => 1 });
		dbus_property('AudioCodecs', [ 'array', 'string' ], 'read', { strict_exceptions => 1 });
		dbus_signal('PropertiesChanged', [ 'string', [ 'dict', 'string', [ 'variant' ] ], [ 'array', 'string' ] ], 'org.freedesktop.DBus.Properties', { param_names => [ 'interface_name', 'changed_properties', 'invalidated_properties' ] });
	}
	sub _dispatch_property { my $self = shift; my $properties = $endpoints{$self->get_object_path()}->{properties}; exists $properties->{$_[0]} ? $properties->{$_[0]} : $self->SUPER::_dispatch_property(@_) }
}
sub main::Endpoint::ConnectAudio { hsphfpd_connect_audio(shift->get_object_path(), @_) }

{
	package main::ClientEndpoint;
	use parent -norequire => 'main::Endpoint';
	use Net::DBus::Exporter 'org.hsphfpd.ClientEndpoint';
	BEGIN {
		dbus_method('SendDisplayTextEvent', [ 'string' ], [], { strict_exceptions => 1, param_names => [ 'text' ] });
	}
}
sub main::ClientEndpoint::SendDisplayTextEvent { hsphfpd_send_text_event(shift->get_object_path(), @_) }

{
	package main::HSPClientEndpoint;
	use parent -norequire => 'main::ClientEndpoint';
	use Net::DBus::Exporter 'org.hsphfpd.HSPClientEndpoint';
	BEGIN {
		dbus_method('SendIncomingCallEvent', [], [], { strict_exceptions => 1 });
	}
}
sub main::ClientEndpoint::SendIncomingCallEvent { hsphfpd_send_ring_event(shift->get_object_path()) }

{
	package main::HFPClientEndpoint;
	use parent -norequire => 'main::ClientEndpoint';
	use Net::DBus::Exporter 'org.hsphfpd.HFPClientEndpoint';
}

{
	package main::GatewayEndpoint;
	use parent -norequire => 'main::Endpoint';
	use Net::DBus::Exporter 'org.hsphfpd.GatewayEndpoint';
	BEGIN {
		dbus_signal('DisplayText', [ 'string' ], { param_names => [ 'text' ] });
	}
}

{
	package main::HSPGatewayEndpoint;
	use parent -norequire => 'main::GatewayEndpoint';
	use Net::DBus::Exporter 'org.hsphfpd.HSPGatewayEndpoint';
	BEGIN {
		dbus_method('SendButtonPressEvent', [], [], { strict_exceptions => 1 });
		dbus_signal('IncomingCall', []);
	}
}
sub main::HSPGatewayEndpoint::SendButtonPressEvent { hsphfpd_send_button_event(shift->get_object_path()) }

{
	package main::HFPGatewayEndpoint;
	use parent -norequire => 'main::GatewayEndpoint';
	use Net::DBus::Exporter 'org.hsphfpd.HFPGatewayEndpoint';
}

{
	package main::Audio;
	use parent 'Net::DBus::Object';
	use Net::DBus::Exporter 'org.hsphfpd.AudioTransport';
	BEGIN {
		dbus_method('Release', [], [], { strict_exceptions => 1 });
		dbus_property('RxVolumeControl', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('TxVolumeControl', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('RxVolumeGain', 'uint16', 'readwrite', { strict_exceptions => 1 });
		dbus_property('TxVolumeGain', 'uint16', 'readwrite', { strict_exceptions => 1 });
		dbus_property('MTU', 'uint16', 'read', { strict_exceptions => 1 });
		dbus_property('AirCodec', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('AgentCodec', 'string', 'read', { strict_exceptions => 1 });
		dbus_property('Endpoint', 'objectpath', 'read', { strict_exceptions => 1 });
		dbus_signal('PropertiesChanged', [ 'string', [ 'dict', 'string', [ 'variant' ] ], [ 'array', 'string' ] ], 'org.freedesktop.DBus.Properties', { param_names => [ 'interface_name', 'changed_properties', 'invalidated_properties' ] });
	}
}
sub main::Audio::Release { hsphfpd_disconnect_audio(shift->get_object_path()) }
sub main::Audio::RxVolumeControl { $endpoints{$audios{shift->get_object_path()}->{endpoint}}->{rx_volume_control} }
sub main::Audio::TxVolumeControl { $endpoints{$audios{shift->get_object_path()}->{endpoint}}->{tx_volume_control} }
sub main::Audio::RxVolumeGain { hsphfpd_rx_volume_gain(shift->get_object_path(), @_) }
sub main::Audio::TxVolumeGain { hsphfpd_tx_volume_gain(shift->get_object_path(), @_) }
sub main::Audio::MTU { $audios{shift->get_object_path()}->{mtu} }
sub main::Audio::AirCodec { $audios{shift->get_object_path()}->{air_codec} }
sub main::Audio::AgentCodec { $audios{shift->get_object_path()}->{agent_codec} }
sub main::Audio::Endpoint { $audios{shift->get_object_path()}->{endpoint} }

{
	package main::Profile;
	use parent 'Net::DBus::Object';
	use Net::DBus::Exporter 'org.bluez.Profile1';
	BEGIN {
		dbus_method('NewConnection', [ 'caller', 'objectpath', 'unixfd', [ 'dict', 'string', [ 'variant' ] ] ], [], { strict_exceptions => 1, param_names => [ 'device', 'socket', 'properties' ] });
		dbus_method('RequestDisconnection', [ 'caller', 'objectpath' ], [], { strict_exceptions => 1, param_names => [ 'device' ] });
		dbus_method('Release', [ 'caller' ], [], { strict_exceptions => 1, no_return => 1 });
	}
}
sub profile_obj_to_name { my $path = $_[0]->get_object_path(); $path =~ s{^.*/}{}; $path }
sub main::Profile::NewConnection { bluez_new_connection(profile_obj_to_name(shift), @_) }
sub main::Profile::RequestDisconnection { bluez_disconnect_connection(profile_obj_to_name(shift), @_) }
sub main::Profile::Release { bluez_release_profile(profile_obj_to_name(shift), @_) }

{
	package main::PowerSupply;
	use parent 'Net::DBus::Object';
	use Net::DBus::Exporter 'org.hsphfpd.PowerSupply';
	BEGIN {
		dbus_property('PowerSource', 'string', 'readwrite', { strict_exceptions => 1 });
		dbus_property('BatteryLevel', 'int16', 'readwrite', { strict_exceptions => 1 });
	}
}
sub main::PowerSupply::PowerSource { shift; hsphfpd_our_power_source(@_) }
sub main::PowerSupply::BatteryLevel { shift; hsphfpd_our_battery_level(@_) }
