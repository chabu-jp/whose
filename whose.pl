#!/usr/bin/perl

use strict;
use warnings;

use Net::DNS;
use Socket ':all';

STDOUT->autoflush;
STDERR->autoflush;

my $ip_address = shift;

my $resolver = Net::DNS::Resolver->new(
	'retry' => 2,
	'retrans' => 1,
	'tcp_timeout' => 4,
	'udp_timeout' => 4,
);

print "\n", 'IP Address: ', $ip_address, "\n";

PTR: {
	my $packet = $resolver->query($ip_address);
	
	if ($packet) {
		foreach my $rr ($packet->answer)
		{
			if ($rr->type eq 'PTR') {
				printf "Hostname  : %s\n\n", $rr->ptrdname;
			}
		}
	} else {
		print 'Hostname  : N/A', "\n\n";
	}
}

AUTHORITY: {
	my $packet = $resolver->send($ip_address, 'SOA', 'IN');
	
	if ($packet->authority) {
		my ($rr) = $packet->authority;
		if ($rr->type eq 'SOA') {
			printf "Authority : %s\n", $rr->name;
			printf "Master    : %s\n", $rr->mname;
			printf "Serial    : %s\n", $rr->serial;
			printf "Email     : %s\n\n", $rr->rname;
		}
	} else {
		print 'Authority : N/A', "\n";
		print 'Master    : N/A', "\n";
		print 'Serial    : N/A', "\n";
		print 'Email     : N/A', "\n\n";
	}
}

my @asn;

PREFIX_INFO: {
	my $qname;
	
	if (index($ip_address, ':') == -1) {
		my @v4 = split(/\./, $ip_address);
		$qname = join('.', @v4[2, 1, 0]) . '.origin.asn.cymru.com.';
	} else {
		my $v6bin = inet_pton(AF_INET6, $ip_address);
		my $v6hex = unpack('H*', $v6bin);
		my $v6pre = substr($v6hex, 0, 16);
		my @v6chr = split(//, $v6pre);
		my @v6rev = reverse @v6chr;
		$qname = join('.', @v6rev) . '.origin6.asn.cymru.com.';
	}
	
	my $packet = $resolver->query($qname, 'TXT', 'IN');
	
	if ($packet) {
		foreach my $rr ($packet->answer)
		{
			if ($rr->type eq 'TXT') {
				my @cols = split(/\s?\|\s?/, $rr->txtdata, -1);
				
				printf "Prefix    : %s\n", $cols[1];
				printf "Origin    : %s\n", $cols[0];
				printf "Country   : %s (%s)\n", $cols[2], uc($cols[3]);
				printf "Allocated : %s\n\n", $cols[4];
				
				push @asn, split(/ /, $cols[0]);
			}
		}
	}
}

my %asn = map { ($_, undef) } @asn;
@asn = sort { $a <=> $b } keys %asn;

AS_INFO: {
	foreach my $asn (@asn)
	{
		my $packet = $resolver->query("AS$asn.asn.cymru.com.", 'TXT', 'IN');
		
		if ($packet) {
			foreach my $rr ($packet->answer)
			{
				if ($rr->type eq 'TXT') {
					my @cols = split(/\s?\|\s?/, $rr->txtdata, -1);
					
					printf "ASN       : %s\n", $cols[0];
					printf "Descr     : %s\n", $cols[4];
					printf "Country   : %s (%s)\n", $cols[1], uc($cols[2]);
					printf "Assigned  : %s\n\n", $cols[3];
				}
			}
		}
	}
}
