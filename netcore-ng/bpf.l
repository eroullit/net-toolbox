%{
#include <netinet/in.h>
#include "y.tab.h"
%}
 
digit         	[0-9]
letter        	[a-zA-Z]
hex		([0-9A-Fa-f][0-9A-Fa-f]?)

MAC		({hex}:{hex}:{hex}:{hex}:{hex}:{hex})
 
%%
dst			{ return DST;       }
src			{ return SRC;       }

vlan			{ return VLAN;      }
mpls			{ return MPLS;      }

arp			{ return ARP;       }
rarp			{ return RARP;      }
ip			{ return IP;        }

tcp			{ return TCP;       }
udp			{ return UDP;       }
icmp			{ return ICMP;      }

host			{ return HOST;      }
net			{ return NET;       }
mask			{ return MASK;      }
port			{ return PORT;      }
portrange		{ return PORTRANGE; }

gateway			{ return GATEWAY;   }

broadcast		{ return BROADCAST; }
multicast		{ return MULTICAST; }

"&&"			{ return AND; }
"||"			{ return OR; }
not			{ return '!'; }

length			{ return LEN; }
inbound			{ return INBOUND; }
outbound		{ return OUTBOUND;}

dev			{ return DEV;}

{MAC}			{ yylval.e = ether_ntoa(yytext)
				return MAC_ID;     	}
{digit}+		{ yylval.num = atoi(yytext);
				return ID;     		}
{digit}\.{digit}\.{digit}\.{digit}\.	{ 
			  yylval.s = strndup(yytext, INET_ADDRSTRLEN);
				return IP_ID;     	}
[ \t\n\r]            /* skip whitespace */
.                    { printf("Unknown character [%c]\n",yytext[0]);
                       return UNKNOWN;    }
%%
 
int yywrap(void){return 1;}

