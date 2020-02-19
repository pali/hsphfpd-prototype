#!/usr/bin/perl
# (C) 2019 Pali

use 5.006;
use strict;
use warnings;

use constant PF_BLUETOOTH => 31;
use constant AF_BLUETOOTH => 31;
use constant SOCK_RAW => 3;
use constant BTPROTO_HCI => 1;
use constant SOL_HCI => 0;
use constant HCI_FILTER => 2;
use constant HCI_COMMAND_PKT => 1;
use constant HCI_EVENT_PKT => 4;
use constant EVT_CMD_COMPLETE => 0x0E;
use constant EVT_CMD_STATUS => 0x0F;
use constant EVT_INQUIRY_COMPLETE => 1;
use constant OGF_HOST_CTL => 3;
use constant OGF_INFO_PARAM => 4;
use constant OCF_READ_VOICE_SETTING => 0x25;
use constant OCF_READ_LOCAL_COMMANDS => 0x02;
use constant OCF_READ_LOCAL_EXT_FEATURES => 0x04;
use constant OCF_READ_LOCAL_CODECS => 0x0B;
use constant HCIGETDEVINFO => 2147764435;

sub hci_cmd {
	my ($sock, $ogf, $ocf, $text, $data) = @_;
	my $opcode = ($ogf << 10) | $ocf;
	setsockopt $sock, SOL_HCI, HCI_FILTER, pack 'VVVv', 0b10000, 0b1100000000000001, 0b1000000000000000000000000000000, $opcode or die "Cannot set HCI_FILTER for $text command on bluetooth socket: $!\n";
	my $req = pack('CvC', HCI_COMMAND_PKT, $opcode, length $data) . $data;
	my $req_len = syswrite $sock, $req or die "Cannot send $text command to bluetooth socket: $!\n";
	die "Cannot send $text command to bluetooth socket: Data were truncated\n" unless length $req == $req_len;
	my $in = ''; vec($in, fileno($sock), 1) = 1;
	my $ret = select my $rout = $in, undef, my $eout = $in, 10;
	die "Cannot wait for $text command response from bluetooth socket: $!\n" if $ret < 0;
	die "No response for $text command from bluetooth socket\n" if $ret == 0;
	my $resp_len = sysread $sock, (my $resp), 1024;
	die "Cannot read $text command response from bluetooth socket: $!\n" unless defined $resp_len;
	die "Invalid response for $text command from bluetooth socket\n" unless $resp_len >= 3 and length $resp >= 3;
	my ($type, $event, $len, $command, $resp_opcode) = unpack 'CCCCv', $resp;
	die "Invalid response for $text command from bluetooth socket\n" unless $type == HCI_EVENT_PKT;
	if ($event == EVT_CMD_STATUS) {
		die "Invalid response for $text command from bluetooth socket\n" unless $len >= 4 and $resp_len >= 7 and length $resp >= 7;
		my ($status, $command, $resp_opcode) = unpack 'CCv', substr $resp, 3;
		die "Invalid response for $text command from bluetooth socket\n" unless $command == EVT_INQUIRY_COMPLETE and $resp_opcode == $opcode and $status;
		die "$text command on bluetooth socket failed: $status\n";
	} elsif ($event == EVT_CMD_COMPLETE) {
		die "Invalid response for $text command from bluetooth socket\n" unless $len >= 3 and $resp_len >= 6 and length $resp >= 6;
		my ($command, $resp_opcode) = unpack 'Cv', substr $resp, 3;
		die "Invalid response for $text command from bluetooth socket\n" unless $command == EVT_INQUIRY_COMPLETE and $resp_opcode == $opcode;
	} else {
		die "Invalid response for $text command from bluetooth socket\n";
	}
	return $len-3, substr $resp, 6;
}

sub hci_local_commands {
	my ($sock) = @_;
	my ($local_commands_len, $local_commands_packed) = hci_cmd($sock, OGF_INFO_PARAM, OCF_READ_LOCAL_COMMANDS, 'READ_LOCAL_COMMANDS', '');
	die "Invalid response for READ_LOCAL_COMMANDS command from bluetooth socket\n" unless $local_commands_len == 65 and length $local_commands_packed >= 65;
	my ($local_commands_status) = unpack 'C', $local_commands_packed;
	die "READ_LOCAL_COMMANDS command on bluetooth socket failed: $local_commands_status" unless $local_commands_status == 0;
	return substr $local_commands_packed, 1;
}

sub hci_ext_features {
	my ($sock) = @_;
	my ($ext_features_len, $ext_features_packed) = hci_cmd($sock, OGF_INFO_PARAM, OCF_READ_LOCAL_EXT_FEATURES, 'READ_LOCAL_EXT_FEATURES', pack 'C', 0);
	die "Invalid response for READ_LOCAL_EXT_FEATURES command from bluetooth socket\n" unless $ext_features_len == 11 and length $ext_features_packed >= 11;
	my ($ext_features_status, $ext_features_page_num, undef, @ext_features) = unpack 'CCCC8', $ext_features_packed;
	die "READ_LOCAL_EXT_FEATURES command on bluetooth socket failed: $ext_features_status" unless $ext_features_status == 0;
	die "Invalid response for READ_LOCAL_EXT_FEATURES command from bluetooth socket\n" unless $ext_features_page_num == 0;
	return @ext_features;
}

sub hci_ext_features_old_way {
	my ($sock) = @_;
	my $dev_info = "\0" x 92;
	ioctl $sock, HCIGETDEVINFO, $dev_info or die "ioctl HCIGETDEVINFO on bluetooth socket failed: $!\n";
	return unpack 'C8', substr $dev_info, 21, 8;
}

sub hci_local_codecs {
	my ($sock) = @_;
	my ($local_codecs_len, $local_codecs_packed) = hci_cmd($sock, OGF_INFO_PARAM, OCF_READ_LOCAL_CODECS, 'READ_LOCAL_CODECS', '');
	die "Invalid response for READ_LOCAL_CODECS command from bluetooth socket\n" unless $local_codecs_len >= 2 and length $local_codecs_packed >= 2;
	my ($local_codecs_status, $local_codecs_count) = unpack 'CC', $local_codecs_packed;
	die "READ_LOCAL_CODECS command on bluetooth socket failed: $local_codecs_status" unless $local_codecs_status == 0;
	die "Invalid response for READ_LOCAL_CODECS command from bluetooth socket\n" unless length $local_codecs_packed >= 2+$local_codecs_count+1;
	my $local_vendor_codecs_count = unpack 'C', substr $local_codecs_packed, 2+$local_codecs_count, 1;
	die "Invalid response for READ_LOCAL_CODECS command from bluetooth socket\n" unless length $local_codecs_packed >= 2+$local_codecs_count+1+4*$local_vendor_codecs_count;
	my @local_codecs = unpack 'C*', substr $local_codecs_packed, 2, $local_codecs_count;
	my @local_vendor_codecs = unpack 'V*', substr $local_codecs_packed, 2+$local_codecs_count+1, 4*$local_vendor_codecs_count;
	return \@local_codecs, \@local_vendor_codecs;
}

sub hci_voice_setting {
	my ($sock) = @_;
	my ($voice_setting_len, $voice_setting_packed) = hci_cmd($sock, OGF_HOST_CTL, OCF_READ_VOICE_SETTING, 'READ_VOICE_SETTING', '');
	die "Invalid response for READ_VOICE_SETTING command from bluetooth socket\n" unless $voice_setting_len == 3 and length $voice_setting_packed >= 3;
	my ($voice_setting_status, $voice_setting) = unpack 'Cv', $voice_setting_packed;
	die "READ_VOICE_SETTING command on bluetooth socket failed: $voice_setting_status" unless $voice_setting_status == 0;
	return $voice_setting;
}

sub hci_sock {
	my ($id) = @_;
	socket my $sock, PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI or die "Cannot open bluetooth socket: $!\n";
	bind $sock, pack 'SS!S!', AF_BLUETOOTH, $id, 0 or die "Cannot bind bluetooth socket to hci device id $id: $!\n";
	return $sock;
}

my $id = $ARGV[0];
die "Usage: $0 hci_id\n" unless defined $id and $id =~ /^[0-9]+$/;

my $sock = hci_sock($id);

my ($local_commands, @ext_features, $local_codecs, $local_vendor_codecs, $voice_setting);

sub hci_call(&) { eval { $_[0]->(); 1 } or do { warn $@; close $sock; $sock = hci_sock($id); 0 } }

hci_call { $local_commands = hci_local_commands($sock) };
hci_call { @ext_features = hci_ext_features($sock) } or hci_call { @ext_features = hci_ext_features_old_way($sock) };
hci_call { ($local_codecs, $local_vendor_codecs) = hci_local_codecs($sock) };
hci_call { $voice_setting = hci_voice_setting($sock) };

print "SCO Commands:\n";
print "\tAdd SCO Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 6, 1) ? 'supported' : 'not supported') . "\n";
print "\tSetup Synchronous Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 131, 1) ? 'supported' : 'not supported') . "\n";
print "\tAccept Synchronous Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 132, 1) ? 'supported' : 'not supported') . "\n";
print "\tReject Synchronous Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 133, 1) ? 'supported' : 'not supported') . "\n";
print "\tEnhanced Setup Synchronous Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 235, 1) ? 'supported' : 'not supported') . "\n";
print "\tEnhanced Accept Synchronous Connection: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 236, 1) ? 'supported' : 'not supported') . "\n";
print "\tRead Local Supported Codecs: " . ((not defined $local_commands) ? 'unknown' : (vec $local_commands, 237, 1) ? 'supported' : 'not supported') . "\n";
print "Connection types:\n";
print "\tSCO link: " . ((not defined $ext_features[1]) ? 'unknown' : ($ext_features[1] & (1 << 3)) ? 'supported' : 'not supported') . "\n";
print "\teSCO link: " . ((not defined $ext_features[3]) ? 'unknown' : ($ext_features[3] & (1 << 7)) ? 'supported' : 'not supported') . "\n";
print "\tEDR eSCO 2 Mbps: " . ((not defined $ext_features[5]) ? 'unknown' : ($ext_features[5] & (1 << 5)) ? 'supported' : 'not supported') . "\n";
print "\tEDR eSCO 3 Mbps: " . ((not defined $ext_features[5]) ? 'unknown' : ($ext_features[5] & (1 << 6)) ? 'supported' : 'not supported') . "\n";
print "\t3-slot EDR eSCO: " . ((not defined $ext_features[5]) ? 'unknown' : ($ext_features[5] & (1 << 7)) ? 'supported' : 'not supported') . "\n";
print "Air Coding Formats:\n";
print "\tu-Law: " . ((not defined $ext_features[1]) ? 'unknown' : ($ext_features[1] & (1 << 6)) ? 'supported' : 'not supported') . "\n";
print "\tA-Law: " . ((not defined $ext_features[1]) ? 'unknown' : ($ext_features[1] & (1 << 7)) ? 'supported' : 'not supported') . "\n";
print "\tCVSD: " . ((not defined $ext_features[2]) ? 'unknown' : ($ext_features[2] & (1 << 0)) ? 'supported' : 'not supported') . "\n";
print "\tTransparent: " . ((not defined $ext_features[2]) ? 'unknown' : ($ext_features[2] & (1 << 3)) ? 'supported' : 'not supported') . "\n";

my %local_codecs;
if ($local_codecs and @{$local_codecs}) {
	%local_codecs = map { $_ => 'supported' } @{$local_codecs};
} else {
	$local_codecs{0x00} = 'expected to be supported' if defined $ext_features[1] and $ext_features[1] & (1 << 6);
	$local_codecs{0x01} = 'expected to be supported' if defined $ext_features[1] and $ext_features[1] & (1 << 7);
	$local_codecs{0x03} = 'expected to be supported' if defined $ext_features[2] and $ext_features[2] & (1 << 3);
	$local_codecs{0x04} = 'expected to be supported';
}
my @cid = qw(u-Law A-Law CVSD Transparent Linear-PCM mSBC);
print "Local Codecs:\n";
print "\t$cid[$_]: " . (exists $local_codecs{$_} ? $local_codecs{$_} : 'not supported') . "\n" foreach 0..$#cid;
printf "\tUnknown Codec 0x%02x: supported\n", $_ foreach grep { $_ > $#cid } sort { $a <=> $b } keys %local_codecs;
print "Local Vendor Codecs:\n";
if ($local_vendor_codecs and @{$local_vendor_codecs}) {
	printf "\tVendor=0x%02x Codec=0x%02x\n", ($_ & 0xFFFF), ($_ >> 4) foreach sort { ($a & 0xFFFF) <=> ($b & 0xFFFF) || ($a >> 4) <=> ($b >> 4) } @{$local_vendor_codecs};
} else {
	print "\t(none supported)\n";
}

my @acf = qw(CVSD u-Law A-Law Transparent);
my @iss = qw(8-bit 16-bit);
my @idf = qw(1's-complement 2's-complement Sign-and-magnitude Unsigned);
my @icf = qw(Linear-PCM u-Law A-Law Reserved);
if (defined $voice_setting) {
	printf "Current voice setting: 0x%04x\n", $voice_setting;
	print "\tAir Coding Format: $acf[$voice_setting & 0x3]\n";
	if (($voice_setting & 0x3) != 3) {
		print "\tInput Coding Format: $icf[($voice_setting & 0x0300) >> 8]\n";
		if ((($voice_setting & 0x0300) >> 8) == 0) {
			print "\t\tInput Data Format: $idf[($voice_setting & 0xc0) >> 6]\n";
			print "\t\tInput Sample Size: $iss[($voice_setting & 0x20) >> 5]\n";
			print "\t\tNumber of bits padding at MSB: ", (($voice_setting & 0x1c) >> 2) . "\n";
		}
	}
} else {
	print "Current voice setting: unknown\n";
}
