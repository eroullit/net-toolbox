/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 */

 /* __LICENSE_HEADER_END__ */


#ifndef _NET_PORTS_UDP_H_
#define _NET_PORTS_UDP_H_

#include <stdint.h>

struct port_udp {
	uint16_t id;
	char *port;
};

/* Partly taken from /etc/services and from Nmap's services file. */
static const struct port_udp ports_udp[] = {
	{1, "tcpmux"},
	{2, "compressnet"},
	{3, "compressnet"},
	{5, "rje"},
	{7, "echo"},
	{9, "discard"},
	{11, "systat"},
	{13, "daytime"},
	{17, "qotd"},
	{18, "msp"},
	{19, "chargen"},
	{20, "ftp-data"},
	{21, "ftp"},
	{22, "ssh"},
	{23, "telnet"},
	{24, "priv-mail"},
	{25, "smtp"},
	{27, "nsw-fe"},
	{29, "msg-icp"},
	{31, "msg-auth"},
	{33, "dsp"},
	{35, "priv-print"},
	{37, "time"},
	{38, "rap"},
	{39, "rlp"},
	{41, "graphics"},
	{42, "nameserver"},
	{43, "whois"},
	{44, "mpm-flags"},
	{45, "mpm"},
	{46, "mpm-snd"},
	{47, "ni-ftp"},
	{48, "auditd"},
	{49, "tacacs"},
	{50, "re-mail-ck"},
	{51, "la-maint"},
	{52, "xns-time"},
	{53, "domain"},
	{54, "xns-ch"},
	{55, "isi-gl"},
	{56, "xns-auth"},
	{57, "priv-term"},
	{58, "xns-mail"},
	{59, "priv-file"},
	{61, "ni-mail"},
	{62, "acas"},
	{63, "via-ftp"},
	{64, "covia"},
	{65, "tacacs-ds"},
	{66, "sqlnet"},
	{67, "dhcps"},
	{68, "dhcpc"},
	{69, "tftp"},
	{70, "gopher"},
	{71, "netrjs-1"},
	{72, "netrjs-2"},
	{73, "netrjs-3"},
	{74, "netrjs-4"},
	{75, "priv-dial"},
	{76, "deos"},
	{77, "priv-rje"},
	{78, "vettcp"},
	{79, "finger"},
	{80, "http"},
	{81, "hosts2-ns"},
	{82, "xfer"},
	{83, "mit-ml-dev"},
	{84, "ctf"},
	{85, "mit-ml-dev"},
	{86, "mfcobol"},
	{88, "kerberos-sec"},
	{89, "su-mit-tg"},
	{90, "dnsix"},
	{91, "mit-dov"},
	{92, "npp"},
	{93, "dcp"},
	{94, "objcall"},
	{95, "supdup"},
	{96, "dixie"},
	{97, "swift-rvf"},
	{98, "tacnews"},
	{99, "metagram"},
	{101, "hostname"},
	{102, "iso-tsap"},
	{103, "gppitnp"},
	{104, "acr-nema"},
	{105, "csnet-ns"},
	{106, "3com-tsmux"},
	{107, "rtelnet"},
	{108, "snagas"},
	{109, "pop2"},
	{110, "pop3"},
	{111, "rpcbind"},
	{112, "mcidas"},
	{113, "auth"},
	{114, "audionews"},
	{115, "sftp"},
	{116, "ansanotify"},
	{117, "uucp-path"},
	{118, "sqlserv"},
	{119, "nntp"},
	{120, "cfdptkt"},
	{121, "erpc"},
	{122, "smakynet"},
	{123, "ntp"},
	{124, "ansatrader"},
	{125, "locus-map"},
	{126, "unitary"},
	{127, "locus-con"},
	{128, "gss-xlicen"},
	{129, "pwdgen"},
	{130, "cisco-fna"},
	{131, "cisco-tna"},
	{132, "cisco-sys"},
	{133, "statsrv"},
	{134, "ingres-net"},
	{135, "msrpc"},
	{136, "profile"},
	{137, "netbios-ns"},
	{138, "netbios-dgm"},
	{139, "netbios-ssn"},
	{140, "emfis-data"},
	{141, "emfis-cntl"},
	{142, "bl-idm"},
	{143, "imap"},
	{144, "news"},
	{145, "uaac"},
	{146, "iso-tp0"},
	{147, "iso-ip"},
	{148, "cronus"},
	{149, "aed-512"},
	{150, "sql-net"},
	{151, "hems"},
	{152, "bftp"},
	{153, "sgmp"},
	{154, "netsc-prod"},
	{155, "netsc-dev"},
	{156, "sqlsrv"},
	{157, "knet-cmp"},
	{158, "pcmail-srv"},
	{159, "nss-routing"},
	{160, "sgmp-traps"},
	{161, "snmp"},
	{162, "snmptrap"},
	{163, "cmip-man"},
	{164, "smip-agent"},
	{165, "xns-courier"},
	{166, "s-net"},
	{167, "namp"},
	{168, "rsvd"},
	{169, "send"},
	{170, "print-srv"},
	{171, "multiplex"},
	{172, "cl-1"},
	{173, "xyplex-mux"},
	{174, "mailq"},
	{175, "vmnet"},
	{176, "genrad-mux"},
	{177, "xdmcp"},
	{178, "nextstep"},
	{179, "bgp"},
	{180, "ris"},
	{181, "unify"},
	{182, "audit"},
	{183, "ocbinder"},
	{184, "ocserver"},
	{185, "remote-kis"},
	{186, "kis"},
	{187, "aci"},
	{188, "mumps"},
	{189, "qft"},
	{190, "cacp"},
	{191, "prospero"},
	{192, "osu-nms"},
	{193, "srmp"},
	{194, "irc"},
	{195, "dn6-nlm-aud"},
	{196, "dn6-smm-red"},
	{197, "dls"},
	{198, "dls-mon"},
	{199, "smux"},
	{200, "src"},
	{201, "at-rtmp"},
	{202, "at-nbp"},
	{203, "at-3"},
	{204, "at-echo"},
	{205, "at-5"},
	{206, "at-zis"},
	{207, "at-7"},
	{208, "at-8"},
	{209, "tam"},
	{210, "z39.50"},
	{211, "914c-g"},
	{212, "anet"},
	{213, "ipx"},
	{214, "vmpwscs"},
	{215, "softpc"},
	{216, "atls"},
	{217, "dbase"},
	{218, "mpp"},
	{219, "uarps"},
	{220, "imap3"},
	{221, "fln-spx"},
	{222, "rsh-spx"},
	{223, "cdc"},
	{242, "direct"},
	{243, "sur-meas"},
	{244, "dayna"},
	{245, "link"},
	{246, "dsp3270"},
	{247, "subntbcst_tftp"},
	{248, "bhfhs"},
	{256, "rap"},
	{257, "set"},
	{258, "yak-chat"},
	{259, "firewall1-rdp"},
	{260, "openport"},
	{261, "nsiiops"},
	{262, "arcisdms"},
	{263, "hdap"},
	{264, "fw1-or-bgmp"},
	{280, "http-mgmt"},
	{281, "personal-link"},
	{282, "cableport-ax"},
	{308, "novastorbakcup"},
	{309, "entrusttime"},
	{310, "bhmds"},
	{311, "asip-webadmin"},
	{312, "vslmp"},
	{313, "magenta-logic"},
	{314, "opalis-robot"},
	{315, "dpsi"},
	{316, "decauth"},
	{317, "zannet"},
	{321, "pip"},
	{344, "pdap"},
	{345, "pawserv"},
	{346, "zserv"},
	{347, "fatserv"},
	{348, "csi-sgwp"},
	{349, "mftp"},
	{350, "matip-type-a"},
	{351, "matip-type-b"},
	{352, "dtag-ste-sb"},
	{353, "ndsauth"},
	{354, "bh611"},
	{355, "datex-asn"},
	{356, "cloanto-net-1"},
	{357, "bhevent"},
	{358, "shrinkwrap"},
	{359, "tenebris_nts"},
	{360, "scoi2odialog"},
	{361, "semantix"},
	{362, "srssend"},
	{363, "rsvp_tunnel"},
	{364, "aurora-cmgr"},
	{365, "dtk"},
	{366, "odmr"},
	{367, "mortgageware"},
	{368, "qbikgdp"},
	{369, "rpc2portmap"},
	{370, "codaauth2"},
	{371, "clearcase"},
	{372, "ulistserv"},
	{373, "legent-1"},
	{374, "legent-2"},
	{375, "hassle"},
	{376, "nip"},
	{377, "tnETOS"},
	{378, "dsETOS"},
	{379, "is99c"},
	{380, "is99s"},
	{381, "hp-collector"},
	{382, "hp-managed-node"},
	{383, "hp-alarm-mgr"},
	{384, "arns"},
	{385, "ibm-app"},
	{386, "asa"},
	{387, "aurp"},
	{388, "unidata-ldm"},
	{389, "ldap"},
	{390, "uis"},
	{391, "synotics-relay"},
	{392, "synotics-broker"},
	{393, "dis"},
	{394, "embl-ndt"},
	{395, "netcp"},
	{396, "netware-ip"},
	{397, "mptn"},
	{398, "kryptolan"},
	{399, "iso-tsap-c2"},
	{400, "work-sol"},
	{401, "ups"},
	{402, "genie"},
	{403, "decap"},
	{404, "nced"},
	{405, "ncld"},
	{406, "imsp"},
	{407, "timbuktu"},
	{408, "prm-sm"},
	{409, "prm-nm"},
	{410, "decladebug"},
	{411, "rmt"},
	{412, "synoptics-trap"},
	{413, "smsp"},
	{414, "infoseek"},
	{415, "bnet"},
	{416, "silverplatter"},
	{417, "onmux"},
	{418, "hyper-g"},
	{419, "ariel1"},
	{420, "smpte"},
	{421, "ariel2"},
	{422, "ariel3"},
	{423, "opc-job-start"},
	{424, "opc-job-track"},
	{425, "icad-el"},
	{426, "smartsdp"},
	{427, "svrloc"},
	{428, "ocs_cmu"},
	{429, "ocs_amu"},
	{430, "utmpsd"},
	{431, "utmpcd"},
	{432, "iasd"},
	{433, "nnsp"},
	{434, "mobileip-agent"},
	{435, "mobilip-mn"},
	{436, "dna-cml"},
	{437, "comscm"},
	{438, "dsfgw"},
	{439, "dasp"},
	{440, "sgcp"},
	{441, "decvms-sysmgt"},
	{442, "cvc_hostd"},
	{443, "https"},
	{444, "snpp"},
	{445, "microsoft-ds"},
	{446, "ddm-rdb"},
	{447, "ddm-dfm"},
	{448, "ddm-ssl"},
	{449, "as-servermap"},
	{450, "tserver"},
	{451, "sfs-smp-net"},
	{452, "sfs-config"},
	{453, "creativeserver"},
	{454, "contentserver"},
	{455, "creativepartnr"},
	{456, "macon"},
	{457, "scohelp"},
	{458, "appleqtc"},
	{459, "ampr-rcmd"},
	{460, "skronk"},
	{461, "datasurfsrv"},
	{462, "datasurfsrvsec"},
	{463, "alpes"},
	{464, "kpasswd5"},
	{465, "smtps"},
	{466, "digital-vrc"},
	{467, "mylex-mapd"},
	{468, "photuris"},
	{469, "rcp"},
	{470, "scx-proxy"},
	{471, "mondex"},
	{472, "ljk-login"},
	{473, "hybrid-pop"},
	{474, "tn-tl-w2"},
	{475, "tcpnethaspsrv"},
	{476, "tn-tl-fd1"},
	{477, "ss7ns"},
	{478, "spsc"},
	{479, "iafserver"},
	{480, "iafdbase"},
	{481, "ph"},
	{482, "xlog"},
	{483, "ulpnet"},
	{484, "integra-sme"},
	{485, "powerburst"},
	{486, "avian"},
	{487, "saft"},
	{488, "gss-http"},
	{489, "nest-protocol"},
	{490, "micom-pfs"},
	{491, "go-login"},
	{492, "ticf-1"},
	{493, "ticf-2"},
	{494, "pov-ray"},
	{495, "intecourier"},
	{496, "pim-rp-disc"},
	{497, "retrospect"},
	{498, "siam"},
	{499, "iso-ill"},
	{500, "isakmp"},
	{501, "stmf"},
	{502, "asa-appl-proto"},
	{503, "intrinsa"},
	{504, "citadel"},
	{505, "mailbox-lm"},
	{506, "ohimsrv"},
	{507, "crs"},
	{508, "xvttp"},
	{509, "snare"},
	{510, "fcp"},
	{511, "passgo"},
	{512, "biff"},
	{513, "who"},
	{514, "syslog"},
	{515, "printer"},
	{516, "videotex"},
	{517, "talk"},
	{518, "ntalk"},
	{519, "utime"},
	{520, "route"},
	{521, "ripng"},
	{522, "ulp"},
	{523, "ibm-db2"},
	{524, "ncp"},
	{525, "timed"},
	{526, "tempo"},
	{527, "stx"},
	{528, "custix"},
	{529, "irc"},
	{530, "courier"},
	{531, "conference"},
	{532, "netnews"},
	{533, "netwall"},
	{534, "mm-admin"},
	{535, "iiop"},
	{536, "opalis-rdv"},
	{537, "nmsp"},
	{538, "gdomap"},
	{539, "apertus-ldp"},
	{540, "uucp"},
	{541, "uucp-rlogin"},
	{542, "commerce"},
	{543, "klogin"},
	{544, "kshell"},
	{545, "appleqtcsrvr"},
	{546, "dhcpv6-client"},
	{547, "dhcpv6-server"},
	{548, "afp"},
	{549, "idfp"},
	{550, "new-rwho"},
	{551, "cybercash"},
	{552, "deviceshare"},
	{553, "pirp"},
	{554, "rtsp"},
	{555, "dsf"},
	{556, "remotefs"},
	{557, "openvms-sysipc"},
	{558, "sdnskmp"},
	{559, "teedtap"},
	{560, "rmonitor"},
	{561, "monitor"},
	{562, "chshell"},
	{563, "snews"},
	{564, "9pfs"},
	{565, "whoami"},
	{567, "banyan-rpc"},
	{568, "ms-shuttle"},
	{569, "ms-rome"},
	{570, "meter"},
	{571, "umeter"},
	{572, "sonar"},
	{573, "banyan-vip"},
	{574, "ftp-agent"},
	{575, "vemmi"},
	{576, "ipcd"},
	{577, "vnas"},
	{578, "ipdd"},
	{579, "decbsrv"},
	{580, "sntp-heartbeat"},
	{581, "bdp"},
	{582, "scc-security"},
	{583, "philips-vc"},
	{584, "keyserver"},
	{585, "imap4-ssl"},
	{586, "password-chg"},
	{587, "submission"},
	{588, "cal"},
	{589, "eyelink"},
	{590, "tns-cml"},
	{591, "http-alt"},
	{592, "eudora-set"},
	{593, "http-rpc-epmap"},
	{594, "tpip"},
	{595, "cab-protocol"},
	{596, "smsd"},
	{597, "ptcnameservice"},
	{598, "sco-websrvrmg3"},
	{599, "acp"},
	{600, "ipcserver"},
	{606, "urm"},
	{607, "nqs"},
	{608, "sift-uft"},
	{609, "npmp-trap"},
	{610, "npmp-local"},
	{611, "npmp-gui"},
	{617, "sco-dtmgr"},
	{623, "asf-rmcp"},
	{626, "serialnumberd"},
	{631, "ipp"},
	{634, "ginad"},
	{635, "mount"},
	{637, "lanserver"},
	{640, "pcnfs"},
	{650, "bwnfs"},
	{660, "mac-srvr-admin"},
	{664, "secure-aux-bus"},
	{666, "doom"},
	{683, "corba-iiop"},
	{704, "elcsd"},
	{709, "entrustmanager"},
	{729, "netviewdm1"},
	{730, "netviewdm2"},
	{731, "netviewdm3"},
	{737, "sometimes-rpc2"},
	{740, "netcp"},
	{741, "netgw"},
	{742, "netrcs"},
	{744, "flexlm"},
	{747, "fujitsu-dev"},
	{748, "ris-cm"},
	{749, "kerberos-adm"},
	{750, "kerberos"},
	{751, "kerberos_master"},
	{752, "qrh"},
	{753, "rrh"},
	{758, "nlogin"},
	{759, "con"},
	{760, "ns"},
	{761, "rxe"},
	{762, "quotad"},
	{763, "cycleserv"},
	{764, "omserv"},
	{765, "webster"},
	{767, "phonebook"},
	{769, "vid"},
	{770, "cadlock"},
	{771, "rtip"},
	{772, "cycleserv2"},
	{773, "notify"},
	{774, "acmaint_dbd"},
	{775, "acmaint_transd"},
	{776, "wpages"},
	{780, "wpgs"},
	{781, "hp-collector"},
	{782, "hp-managed-node"},
	{786, "concert"},
	{800, "mdbs_daemon"},
	{801, "device"},
	{888, "accessbuilder"},
	{989, "ftps-data"},
	{990, "ftps"},
	{996, "vsinet"},
	{997, "maitrd"},
	{998, "puparp"},
	{999, "applix"},
	{1000, "ock"},
	{1008, "ufsd"},
	{1012, "sometimes-rpc1"},
	{1025, "blackjack"},
	{1026, "win-rpc"},
	{1028, "ms-lsa"},
	{1030, "iad1"},
	{1031, "iad2"},
	{1032, "iad3"},
	{1034, "activesync-notify"},
	{1043, "boinc"},
	{1051, "optima-vnet"},
	{1052, "ddt"},
	{1055, "ansyslmd"},
	{1058, "nim"},
	{1059, "nimreg"},
	{1060, "polestar"},
	{1062, "veracity"},
	{1066, "fpo-fns"},
	{1067, "instl_boots"},
	{1068, "instl_bootc"},
	{1069, "cognex-insight"},
	{1080, "socks"},
	{1083, "ansoft-lm-1"},
	{1084, "ansoft-lm-2"},
	{1110, "nfsd-keepalive"},
	{1155, "nfa"},
	{1167, "cisco-ipsla"},
	{1212, "lupa"},
	{1214, "fasttrack"},
	{1222, "nerv"},
	{1248, "hermes"},
	{1346, "alta-ana-lm"},
	{1347, "bbn-mmc"},
	{1348, "bbn-mmx"},
	{1349, "sbook"},
	{1350, "editbench"},
	{1351, "equationbuilder"},
	{1352, "lotusnotes"},
	{1353, "relief"},
	{1354, "rightbrain"},
	{1355, "intuitive-edge"},
	{1356, "cuillamartin"},
	{1357, "pegboard"},
	{1358, "connlcli"},
	{1359, "ftsrv"},
	{1360, "mimer"},
	{1361, "linx"},
	{1362, "timeflies"},
	{1363, "ndm-requester"},
	{1364, "ndm-server"},
	{1365, "adapt-sna"},
	{1366, "netware-csp"},
	{1367, "dcs"},
	{1368, "screencast"},
	{1369, "gv-us"},
	{1370, "us-gv"},
	{1371, "fc-cli"},
	{1372, "fc-ser"},
	{1373, "chromagrafx"},
	{1374, "molly"},
	{1375, "bytex"},
	{1376, "ibm-pps"},
	{1377, "cichlid"},
	{1378, "elan"},
	{1379, "dbreporter"},
	{1380, "telesis-licman"},
	{1381, "apple-licman"},
	{1383, "gwha"},
	{1384, "os-licman"},
	{1385, "atex_elmd"},
	{1386, "checksum"},
	{1387, "cadsi-lm"},
	{1388, "objective-dbc"},
	{1389, "iclpv-dm"},
	{1390, "iclpv-sc"},
	{1391, "iclpv-sas"},
	{1392, "iclpv-pm"},
	{1393, "iclpv-nls"},
	{1394, "iclpv-nlc"},
	{1395, "iclpv-wsm"},
	{1396, "dvl-activemail"},
	{1397, "audio-activmail"},
	{1398, "video-activmail"},
	{1399, "cadkey-licman"},
	{1400, "cadkey-tablet"},
	{1401, "goldleaf-licman"},
	{1402, "prm-sm-np"},
	{1403, "prm-nm-np"},
	{1404, "igi-lm"},
	{1405, "ibm-res"},
	{1406, "netlabs-lm"},
	{1407, "dbsa-lm"},
	{1408, "sophia-lm"},
	{1409, "here-lm"},
	{1410, "hiq"},
	{1411, "af"},
	{1412, "innosys"},
	{1413, "innosys-acl"},
	{1414, "ibm-mqseries"},
	{1415, "dbstar"},
	{1416, "novell-lu6.2"},
	{1417, "timbuktu-srv1"},
	{1418, "timbuktu-srv2"},
	{1419, "timbuktu-srv3"},
	{1420, "timbuktu-srv4"},
	{1421, "gandalf-lm"},
	{1422, "autodesk-lm"},
	{1423, "essbase"},
	{1424, "hybrid"},
	{1425, "zion-lm"},
	{1426, "sas-1"},
	{1427, "mloadd"},
	{1428, "informatik-lm"},
	{1429, "nms"},
	{1430, "tpdu"},
	{1431, "rgtp"},
	{1432, "blueberry-lm"},
	{1433, "ms-sql-s"},
	{1434, "ms-sql-m"},
	{1435, "ibm-cics"},
	{1436, "sas-2"},
	{1437, "tabula"},
	{1438, "eicon-server"},
	{1439, "eicon-x25"},
	{1440, "eicon-slp"},
	{1441, "cadis-1"},
	{1442, "cadis-2"},
	{1443, "ies-lm"},
	{1444, "marcam-lm"},
	{1445, "proxima-lm"},
	{1446, "ora-lm"},
	{1447, "apri-lm"},
	{1448, "oc-lm"},
	{1449, "peport"},
	{1450, "dwf"},
	{1451, "infoman"},
	{1452, "gtegsc-lm"},
	{1453, "genie-lm"},
	{1454, "interhdl_elmd"},
	{1455, "esl-lm"},
	{1456, "dca"},
	{1457, "valisys-lm"},
	{1458, "nrcabq-lm"},
	{1459, "proshare1"},
	{1460, "proshare2"},
	{1461, "ibm_wrless_lan"},
	{1462, "world-lm"},
	{1463, "nucleus"},
	{1464, "msl_lmd"},
	{1465, "pipes"},
	{1466, "oceansoft-lm"},
	{1467, "csdmbase"},
	{1468, "csdm"},
	{1469, "aal-lm"},
	{1470, "uaiact"},
	{1471, "csdmbase"},
	{1472, "csdm"},
	{1473, "openmath"},
	{1474, "telefinder"},
	{1475, "taligent-lm"},
	{1476, "clvm-cfg"},
	{1477, "ms-sna-server"},
	{1478, "ms-sna-base"},
	{1479, "dberegister"},
	{1480, "pacerforum"},
	{1481, "airs"},
	{1482, "miteksys-lm"},
	{1483, "afs"},
	{1484, "confluent"},
	{1485, "lansource"},
	{1486, "nms_topo_serv"},
	{1487, "localinfosrvr"},
	{1488, "docstor"},
	{1489, "dmdocbroker"},
	{1490, "insitu-conf"},
	{1491, "anynetgateway"},
	{1492, "stone-design-1"},
	{1493, "netmap_lm"},
	{1494, "citrix-ica"},
	{1495, "cvc"},
	{1496, "liberty-lm"},
	{1497, "rfx-lm"},
	{1498, "watcom-sql"},
	{1499, "fhc"},
	{1500, "vlsi-lm"},
	{1501, "sas-3"},
	{1502, "shivadiscovery"},
	{1503, "imtc-mcs"},
	{1504, "evb-elm"},
	{1505, "funkproxy"},
	{1506, "utcd"},
	{1507, "symplex"},
	{1508, "diagmond"},
	{1509, "robcad-lm"},
	{1510, "mvx-lm"},
	{1511, "3l-l1"},
	{1512, "wins"},
	{1513, "fujitsu-dtc"},
	{1514, "fujitsu-dtcns"},
	{1515, "ifor-protocol"},
	{1516, "vpad"},
	{1517, "vpac"},
	{1518, "vpvd"},
	{1519, "vpvc"},
	{1520, "atm-zip-office"},
	{1521, "ncube-lm"},
	{1522, "rna-lm"},
	{1523, "cichild-lm"},
	{1524, "ingreslock"},
	{1525, "oracle"},
	{1526, "pdap-np"},
	{1527, "tlisrv"},
	{1528, "mciautoreg"},
	{1529, "coauthor"},
	{1530, "rap-service"},
	{1531, "rap-listen"},
	{1532, "miroconnect"},
	{1533, "virtual-places"},
	{1534, "micromuse-lm"},
	{1535, "ampr-info"},
	{1536, "ampr-inter"},
	{1537, "sdsc-lm"},
	{1538, "3ds-lm"},
	{1539, "intellistor-lm"},
	{1540, "rds"},
	{1541, "rds2"},
	{1542, "gridgen-elmd"},
	{1543, "simba-cs"},
	{1544, "aspeclmd"},
	{1545, "vistium-share"},
	{1546, "abbaccuray"},
	{1547, "laplink"},
	{1548, "axon-lm"},
	{1549, "shivasound"},
	{1550, "3m-image-lm"},
	{1551, "hecmtl-db"},
	{1552, "pciarray"},
	{1600, "issd"},
	{1645, "radius"},
	{1646, "radacct"},
	{1650, "nkd"},
	{1651, "shiva_confsrvr"},
	{1652, "xnmp"},
	{1661, "netview-aix-1"},
	{1662, "netview-aix-2"},
	{1663, "netview-aix-3"},
	{1664, "netview-aix-4"},
	{1665, "netview-aix-5"},
	{1666, "netview-aix-6"},
	{1667, "netview-aix-7"},
	{1668, "netview-aix-8"},
	{1669, "netview-aix-9"},
	{1670, "netview-aix-10"},
	{1671, "netview-aix-11"},
	{1672, "netview-aix-12"},
	{1701, "L2TP"},
	{1718, "h225gatedisc"},
	{1719, "h323gatestat"},
	{1782, "hp-hcip"},
	{1812, "radius"},
	{1813, "radacct"},
	{1900, "upnp"},
	{1986, "licensedaemon"},
	{1987, "tr-rsrb-p1"},
	{1988, "tr-rsrb-p2"},
	{1989, "tr-rsrb-p3"},
	{1990, "stun-p1"},
	{1991, "stun-p2"},
	{1992, "stun-p3"},
	{1993, "snmp-tcp-port"},
	{1994, "stun-port"},
	{1995, "perf-port"},
	{1996, "tr-rsrb-port"},
	{1997, "gdp-port"},
	{1998, "x25-svc-port"},
	{1999, "tcp-id-port"},
	{2000, "cisco-sccp"},
	{2001, "wizard"},
	{2002, "globe"},
	{2004, "emce"},
	{2005, "oracle"},
	{2006, "raid-cc"},
	{2007, "raid-am"},
	{2008, "terminaldb"},
	{2009, "whosockami"},
	{2010, "pipe_server"},
	{2011, "servserv"},
	{2012, "raid-ac"},
	{2013, "raid-cd"},
	{2014, "raid-sf"},
	{2015, "raid-cs"},
	{2016, "bootserver"},
	{2017, "bootclient"},
	{2018, "rellpack"},
	{2019, "about"},
	{2020, "xinupageserver"},
	{2021, "xinuexpansion1"},
	{2022, "xinuexpansion2"},
	{2023, "xinuexpansion3"},
	{2024, "xinuexpansion4"},
	{2025, "xribs"},
	{2026, "scrabble"},
	{2027, "shadowserver"},
	{2028, "submitserver"},
	{2030, "device2"},
	{2032, "blackboard"},
	{2033, "glogger"},
	{2034, "scoremgr"},
	{2035, "imsldoc"},
	{2038, "objectmanager"},
	{2040, "lam"},
	{2041, "interbase"},
	{2042, "isis"},
	{2043, "isis-bcast"},
	{2044, "rimsl"},
	{2045, "cdfunc"},
	{2046, "sdfunc"},
	{2047, "dls"},
	{2048, "dls-monitor"},
	{2049, "nfs"},
	{2065, "dlsrpn"},
	{2067, "dlswpn"},
	{2103, "zephyr-clt"},
	{2104, "zephyr-hm"},
	{2105, "eklogin"},
	{2106, "ekshell"},
	{2108, "rkinit"},
	{2148, "veritas-ucl"},
	{2201, "ats"},
	{2222, "msantipiracy"},
	{2232, "ivs-video"},
	{2241, "ivsd"},
	{2307, "pehelp"},
	{2401, "cvspserver"},
	{2430, "venus"},
	{2431, "venus-se"},
	{2432, "codasrv"},
	{2433, "codasrv-se"},
	{2500, "rtsserv"},
	{2501, "rtsclient"},
	{2627, "webster"},
	{2784, "www-dev"},
	{2904, "m2ua"},
	{2944, "megaco-h248"},
	{2948, "wap-push"},
	{2967, "symantec-av"},
	{3049, "cfs"},
	{3130, "squid-ipc"},
	{3141, "vmodem"},
	{3246, "kademlia"},
	{3264, "ccmail"},
	{3283, "netassistant"},
	{3333, "dec-notes"},
	{3389, "ms-term-serv"},
	{3401, "squid-snmp"},
	{3421, "bmap"},
	{3455, "prsvp"},
	{3456, "IISrpc-or-vat"},
	{3457, "vat-control"},
	{3531, "peerenabler"},
	{3900, "udt_os"},
	{3984, "mapper-nodemgr"},
	{3985, "mapper-mapethd"},
	{3986, "mapper-ws_ethd"},
	{3996, "remoteanything"},
	{3997, "remoteanything"},
	{3998, "remoteanything"},
	{4000, "icq"},
	{4008, "netcheque"},
	{4045, "lockd"},
	{4132, "nuts_dem"},
	{4133, "nuts_bootp"},
	{4321, "rwhois"},
	{4343, "unicall"},
	{4444, "krb524"},
	{4500, "nat-t-ike"},
	{4666, "edonkey"},
	{4672, "rfa"},
	{4827, "squid-htcp"},
	{5000, "upnp"},
	{5001, "commplex-link"},
	{5002, "rfe"},
	{5003, "filemaker"},
	{5010, "telelpathstart"},
	{5011, "telelpathattack"},
	{5050, "mmcc"},
	{5060, "sip"},
	{5061, "sip-tls"},
	{5145, "rmonitor_secure"},
	{5190, "aol"},
	{5191, "aol-1"},
	{5192, "aol-2"},
	{5193, "aol-3"},
	{5222, "xmpp"},
	{5236, "padl2sim"},
	{5300, "hacl-hb"},
	{5301, "hacl-gs"},
	{5302, "hacl-cfg"},
	{5303, "hacl-probe"},
	{5304, "hacl-local"},
	{5305, "hacl-test"},
	{5308, "cfengine"},
	{5353, "zeroconf"},
	{5428, "omid"},
	{5500, "securid"},
	{5540, "sdxauthd"},
	{5555, "rplay"},
	{5632, "pcanywherestat"},
	{5713, "proshareaudio"},
	{5714, "prosharevideo"},
	{5715, "prosharedata"},
	{5716, "prosharerequest"},
	{5717, "prosharenotify"},
	{6000, "X11"},
	{6001, "X11:1"},
	{6002, "X11:2"},
	{6004, "X11:4"},
	{6110, "softcm"},
	{6111, "spc"},
	{6141, "meta-corp"},
	{6142, "aspentec-lm"},
	{6143, "watershed-lm"},
	{6144, "statsci1-lm"},
	{6145, "statsci2-lm"},
	{6146, "lonewolf-lm"},
	{6147, "montage-lm"},
	{6148, "ricardo-lm"},
	{6346, "gnutella"},
	{6347, "gnutella2"},
	{6502, "netop-rc"},
	{6549, "powerchuteplus"},
	{6558, "xdsxdm"},
	{6969, "acmsoda"},
	{7000, "afs3-fileserver"},
	{7001, "afs3-callback"},
	{7002, "afs3-prserver"},
	{7003, "afs3-vlserver"},
	{7004, "afs3-kaserver"},
	{7005, "afs3-volser"},
	{7006, "afs3-errors"},
	{7007, "afs3-bos"},
	{7008, "afs3-update"},
	{7009, "afs3-rmtsys"},
	{7010, "ups-onlinet"},
	{7100, "font-service"},
	{7200, "fodms"},
	{7201, "dlip"},
	{7648, "cucme-1"},
	{7649, "cucme-2"},
	{7650, "cucme-3"},
	{7651, "cucme-4"},
	{8193, "sophos"},
	{8471, "pim-port"},
	{9000, "cslistener"},
	{9200, "wap-wsp"},
	{9535, "man"},
	{9595, "pds"},
	{9876, "sd"},
	{10080, "amanda"},
	{16444, "overnet"},
	{17007, "isode-dua"},
	{17185, "wdbrpc"},
	{18000, "biimenu"},
	{20031, "bakbonenetvault"},
	{22370, "hpnpd"},
	{26000, "quake"},
	{26900, "hexen2"},
	{27015, "halflife"},
	{27444, "Trinoo_Bcast"},
	{27500, "quakeworld"},
	{27910, "quake2"},
	{27960, "quake3"},
	{28910, "heretic2"},
	{31335, "Trinoo_Register"},
	{31337, "BackOrifice"},
	{32768, "omad"},
	{32770, "sometimes-rpc4"},
	{32771, "sometimes-rpc6"},
	{32772, "sometimes-rpc8"},
	{32773, "sometimes-rpc10"},
	{32774, "sometimes-rpc12"},
	{32775, "sometimes-rpc14"},
	{32776, "sometimes-rpc16"},
	{32777, "sometimes-rpc18"},
	{32778, "sometimes-rpc20"},
	{32779, "sometimes-rpc22"},
	{32780, "sometimes-rpc24"},
	{32786, "sometimes-rpc26"},
	{32787, "sometimes-rpc28"},
	{38037, "landesk-cba"},
	{38293, "landesk-cba"},
	{39213, "sygatefw"},
	{45000, "ciscopop"},
	{47557, "dbbrowse"},
	{54321, "bo2k"},
};

static const char port_udp_unknown[] = "Unknown";

void udp_ports_hash_destroy(void);
int udp_ports_hash_init(void);
int udp_ports_hash_search(const uint16_t udp, const char ** port_name);

#endif				/* _NET_PORTS_UDP_H_ */
