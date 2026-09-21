<?php

namespace App\Services;

class MitigationPlaybookService
{
    /**
     * Generate mitigation playbooks for routers and Flowspec daemons.
     */
    public function generatePlaybooks(string $prefix, ?int $rogueAsn = null, string $incidentType = 'SUBPREFIX_HIJACK'): array
    {
        $flowspecJunos = <<<JUNOS
# Juniper Junos BGP Flowspec Mitigation Rule
set firewall family inet flow route drop-rogue-flow match destination {$prefix}
set firewall family inet flow route drop-rogue-flow then discard
commit comment "BGP-Shield Automated Sentinel Mitigation for {$prefix}"
JUNOS;

        $flowspecCisco = <<<CISCO
! Cisco IOS-XR BGP Flowspec Policy (RFC 5575)
flowspec
 local-install interface all
 address-family ipv4
  class-map type traffic match-all CM-DROP-ROGUE-{$rogueAsn}
   match destination-address {$prefix}
  !
  policy-map type traffic PM-BGP-SHIELD-DROP
   class CM-DROP-ROGUE-{$rogueAsn}
    drop
  !
!
CISCO;

        $rtbhBird = <<<BIRD
# BIRD Routing Daemon RTBH Blackhole Trigger
filter rtbh_mitigation {
    if net = {$prefix} then {
        bgp_community.add((65535, 666)); # RFC 7999 Blackhole
        dest = RTD_BLACKHOLE;
        accept;
    }
}
BIRD;

        $asFilter = "";
        if ($rogueAsn) {
            $asFilter = <<<CISCO
! Cisco IOS-XR AS-Path Filter to Reject Rogue Origin
as-path-set ROGUE-ASN-{$rogueAsn}
  ios-regex '_{$rogueAsn}$'
end-set
!
route-policy DROP-ROGUE-ORIGIN
  if as-path in ROGUE-ASN-{$rogueAsn} then
    drop
  endif
end-policy
CISCO;
        }

        return [
            'flowspec_junos' => $flowspecJunos,
            'flowspec_cisco' => $flowspecCisco,
            'rtbh_bird' => $rtbhBird,
            'as_filter_cisco' => $asFilter,
        ];
    }
}
