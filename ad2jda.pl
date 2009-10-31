#!/usr/bin/perl
#
# This script is written by Ismael Lezcano
# Make no unauthorized changes and CERTAINLY don't take any credit
# for this work.
#
#
# version 3 2/16/09: Instituted 100 count increments for queries
# 		: changed default configuration input file name
# 		: Made allowances for 0 member groups
#
# version 4 2/17/09
# 		: Made output of all samAccount attribs lower case
# 		: Changed output to include namespace and XML declarations
# version 5 2/17/09
#		: Script will now remove any childless nodes from the document element

use XML::DOM;
#use XML::Dumper;
#use Data::Dumper;
use Net::LDAP;
use Net::DNS;
use Authen::SASL qw(Perl);
use Getopt::Std;
use strict;

# Variables
our $VERSION = 5;
$Getopt::Std::STANDARD_HELP_VERSION = 1;
my $res=Net::DNS::Resolver->new;
my $parser = new XML::DOM::Parser;
my $aduser;
my $adpassword;
my %adgroups;
my %roleids;
my $mesg;
my %dn2sam;
my $totalusers = 0;
my @mainuserlist;
my %shellopts = ('c' => 'ldap_config.xml',
		'o' => 'import.xml');
my %ldap2xmlattribs = ( 'mail' => 'email',
		'cn' => 'fullName',
		'givenName' => 'firstName',
		'sn' => 'lastName',
		'telephone' => 'telephone',
		'fax' => 'fax',
		'title' => 'title',
		'c' => 'country',
		#'l' => 'locality'
		);

# Junks

my $n = 0;

# Parse config file

# Parse CLI opts

getopts("c:o:", \%shellopts);
my $configfile = $parser->parsefile($shellopts{'c'});

my $adcreds = $configfile->getElementsByTagName('adcredentials');

if ($adcreds->getLength() == 1)
	{
	my $node = $adcreds->item(0);
	$aduser = $node->getAttribute('username');
	$adpassword = $node->getAttribute('password');
	}
else
	{die}

my $nodeset = $configfile->getElementsByTagName('group');
$n = $nodeset->getLength();

for (my $i = 0; $i < $n; $i++)
	{
	my $node = $nodeset->item($i);
	$adgroups{$node->getAttribute('adgroup')} = $node->getAttribute('roleid');
	}

%roleids = map {$_, []} values %adgroups;

$configfile->dispose();
$configfile = new XML::DOM::Document;

# Create SASL creds

my $sasl = Authen::SASL->new(mechanism => 'DIGEST-MD5',
                        callback => {
                                user => $aduser,
                                pass => $adpassword,
                                },
                        );

# Find LDAP Servers

my $query = $res->query('_gc._tcp.rye._sites.avonet.net', 'SRV');
my @gcloginservers = map {"ldap://". $_->target . ":" . $_->port} $query->answer;
@gcloginservers = grep (/na.avonet.net/, @gcloginservers);

# Bind to LDAP

my $ldapgc = Net::LDAP->new(\@gcloginservers, async => 0);

$mesg = $ldapgc->bind(sasl =>$sasl);

$mesg->code && die $mesg->error;

# Structurize import.xml

$configfile->setXMLDecl($configfile->createXMLDecl('1.0', 'UTF-8'));
my $outputroot = $configfile->createElement('admin');
my $createnode = $configfile->createElement('create');
my $deletenode = $configfile->createElement('delete');
$configfile->appendChild($outputroot);
$outputroot->appendChild($createnode);
$outputroot->appendChild($deletenode);
$outputroot->setAttribute('xmlns:xsi'=>'http://www.w3.org/2001/XMLSchema-instance');
$outputroot->setAttribute('xsi:noNamespaceSchemaLocation'=>'csm_admin.xsd');

my $avonnode = $configfile->createElement('enterpriseName');
$avonnode->appendChild($configfile->createTextNode('Avon'));

# Search for Members of Groups
foreach my $adgroup (keys %adgroups)
	{
	my $searchobj = $ldapgc->search(base => 'dc=na,dc=avonet,dc=net',
		scope=>'sub',
		filter => "(&(objectClass=group)(cn=$adgroup))",
		attrs => ['member'],
		);

	$mesg->code && die $mesg->error;
	
	my $ldapentry = $searchobj->shift_entry;
	next unless ($ldapentry && $ldapentry->exists('member'));
	my $membersref = $ldapentry->get_value('member', asref=>1);
	push (@mainuserlist, @$membersref);
	my $arrayref = $roleids{$adgroups{$adgroup}};
	push (@$arrayref, @$membersref);

	}

# Weed out duplicates

if (@mainuserlist > 1)
	{
	local $\ = "\n";
	print "User List contains " . @mainuserlist . " records. Removing Duplicates";
	my %hash = map {$_, 1} @mainuserlist;
	@mainuserlist = keys %hash;
	$totalusers = scalar @mainuserlist;
	print "User List now contains $totalusers records.";
	}

$ldapgc->async(1);

my $usercount = 0;

# Get Each User
foreach my $user (@mainuserlist)
	{
	local $| = 1;
	my $searchobj = $ldapgc->search(base => $user,
		scope=>'base',
		filter => '(objectClass=user)',
		attrs => [keys %ldap2xmlattribs, 'sAMAccountName', 'useraccountcontrol'],
		callback=>\&entriesrouting,
		);

	printf ("Working on %4u of %4u users\r", ++$usercount, $totalusers);

	$ldapgc->sync if ($usercount % 100 == 0);
	}

$ldapgc->sync;

$ldapgc->unbind;

print "\nAssigning user roles\n";

foreach my $roleid (keys %roleids)
	{
	
	my $arrayref = $roleids{$roleid};
	foreach my $dn (@$arrayref)
		{
		my $userolenode = $configfile->createElement('userRole');
		$userolenode->setAttribute('userName' =>$dn2sam{$dn});
		$userolenode->setAttribute('roleId' =>$roleid);
		$createnode->appendChild($userolenode);
		}
	}

print "Pruning empty sections of output.\n";

foreach my $node ($outputroot->getChildNodes())
	{
	next if $node->hasChildNodes();
	$outputroot->removeChild($node);
	}

print "Writing $shellopts{'o'}\n";


$configfile->printToFile($shellopts{'o'});

print "DONE!\n";
#
# FUNCTIONS
#

sub entriesrouting
	{
	(my $mesg, my $entry) = @_;
	return unless $entry;

	my $dn = $entry->dn();
	my $sam = $entry->get_value('sAMAccountName');
	$sam = lc($sam);
	$dn2sam{$dn}=$sam;
	my $uac = $entry->get_value('userAccountControl');
	$n = $uac & 0x002;
	if ($n == 2)
		{

		my $usernode = $configfile->createElement('userKey');
		$usernode->setAttribute('userName' => $sam);
		$deletenode->appendChild($usernode);

		foreach my $arrayref (values %roleids)
			{
			@$arrayref = grep (!/$dn/i, @$arrayref);
			}
		}
	else
		{
		
		my $usernode = $configfile->createElement('user');
		$usernode->setAttribute('userName' => $sam);
		$usernode->appendChild($avonnode->cloneNode(1));

		my ($locality) = $dn =~ /dc=(\w{2}),dc=avonet,dc=net/i;
		if ($locality)
			{
			$locality = uc($locality);
			$locality =~ s/^S/L/;
			my $textnode = $configfile->createTextNode($locality);
			my $tempnode = $configfile->createElement('locality');
			$tempnode->appendChild($textnode);
			$usernode->appendChild($tempnode);
			}

		foreach my $attrib (keys %ldap2xmlattribs)
			{
			my $tempnode = $configfile->createElement($ldap2xmlattribs{$attrib});
			my $textdata = $entry->exists($attrib) ? $entry->get_value($attrib) : '';
			if (length($textdata) > 0)
				{
				$tempnode->appendChild($configfile->createTextNode($textdata));
				}
			$usernode->appendChild($tempnode);
			}
		$createnode->appendChild($usernode);	

		}
	return;
	}

sub HELP_MESSAGE
	{
	print "\n$0 [OPTIONS]|--help|--version
	
	OPTIONS:
	--help (this message)
	-c Configuration XML file (default: ldap_config.xml)
	-o Output XML file (default: import.xml)\n";
	exit 0;
	}
