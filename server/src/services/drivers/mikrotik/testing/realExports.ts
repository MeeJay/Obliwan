/**
 * REAL exports, off production hardware. Not written by hand.
 *
 * Everything in the NCM was built against fakes and fixtures, which is the
 * project's method and a sound one. But a fake is written by the same person
 * who wrote the parser, so it encodes the same assumptions — including the
 * wrong ones. The first genuine `/export` handed over by an operator found a
 * defect in `unfoldLines()` that had been there since M4 and that no
 * hand-written fixture had ever exercised.
 *
 * Add to this file rather than inventing: a transcript costs one command and is
 * worth more than any fixture we can imagine.
 */

/**
 * `/ip dhcp-client/export` — RouterOS 7.20.6, a live CPE.
 *
 * WHAT MAKES IT VALUABLE, and why it broke the parser:
 *  - the value of `script=` is WRAPPED across four continuation lines, because
 *    the collector allocates a pty and RouterOS wraps at the terminal width;
 *  - the wrapped value is a quoted string containing `\n`, `\"` and `\$`, so
 *    every escape path is exercised at once;
 *  - and the script itself is load-bearing configuration: it re-points two
 *    static routes at whatever gateway the lease hands out. That is the site's
 *    WAN failover living inside a DHCP client.
 */
export const DHCP_CLIENT_WRAPPED_SCRIPT = String.raw`# 2026-08-30 21:23:26 by RouterOS 7.20.6
# software id = 89D6-MZE1
#
# model = L41G-2axD&FG621-EA
# serial number = HGW0A0M2QM2
/ip dhcp-client
add add-default-route=no comment="WAN1 DHCP" interface=ether1-WAN1 script=\
    ":if (\$bound=1) do={\
    \n    /ip/route/set [find where comment=\"NW-WAN1\"] dst-address=8.8.8.8/32 gateway=\$\"gateway-address\"\
    \n    /ip/route/set [find where comment=\"WAN1-GW\"] dst-address=0.0.0.0/0 gateway=\$\"gateway-address\"\
    \n}" use-peer-dns=no use-peer-ntp=no
`;

/**
 * The same script as the operator sees it in the web UI — the GROUND TRUTH the
 * parser must reproduce. Supplied alongside the export precisely so the test
 * asserts against what a human would recognise, not against whatever the
 * parser happens to produce.
 */
export const DHCP_CLIENT_SCRIPT_AS_SEEN = [
  ':if ($bound=1) do={',
  '    /ip/route/set [find where comment="NW-WAN1"] dst-address=8.8.8.8/32 gateway=$"gateway-address"',
  '    /ip/route/set [find where comment="WAN1-GW"] dst-address=0.0.0.0/0 gateway=$"gateway-address"',
  '}',
].join('\n');
