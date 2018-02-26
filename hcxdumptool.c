#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <pthread.h>

#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#endif

#include "include/version.h"
#include "include/hcxdumptool.h"
#include "include/ieee80211.c"
#include "include/pcap.c"
#include "include/strings.c"
#include "include/hashops.c"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

/*===========================================================================*/
/* global var */

static int fd_socket = 0;
static int fd_pcap = 0;
static int fd_ippcap = 0;

static uint32_t myouiap = 0;
static uint32_t mynicap = 0;
static uint32_t myouista = 0;
static uint32_t mynicsta = 0;
static uint32_t mysequencenr = 0;
static uint64_t mytime = 0;

static int staytime = TIME_INTERVAL;
static uint8_t cpa = 0;

static char *interfacename = NULL;
static char *pcapoutname = NULL;
static char *ippcapoutname = NULL;

static macessidlist_t *macapessidliste = NULL;
static macessidlist_t *macstaessidliste = NULL;

static int errorcause = EXIT_SUCCESS;
static int errorcount = 0;
static int maxerrorcount = 1000000;

static bool wantstopflag = false;
static bool wantstatusflag = false;
static bool showinterfaces = false;
static bool poweroffflag = false;
static bool channelsetflag = false;
static bool deauthflag = false;
static bool requestflag = false;
static bool respondflag = false;


static const uint8_t hdradiotap[] =
{
0x00, 0x00, // <-- radiotap version
0x0c, 0x00, // <- radiotap header length
0x04, 0x80, 0x00, 0x00, // <-- bitmap
0x02, // <-- rate
0x00, // <-- padding for natural alignment
0x18, 0x00, // <-- TX flags
};
#define HDRRT_SIZE sizeof(hdradiotap)



static uint8_t channeldefaultlist[38] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
36, 40, 44, 48, 52, 56, 60, 64,
100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 147, 151, 155, 167,
0
};

static uint8_t channelscanlist[128] =
{
1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static uint8_t mac_myap[6];
static uint8_t mac_mysta[6];

struct timeval tv;
struct timeval tvfd;

pcaprec_hdr_t *pkh;
uint8_t *packet_ptr;
mac_t *mac_ptr;
ietag_t *essid_tag;

int caplen;
uint8_t packetin[PCAP_SNAPLEN +PCAPREC_SIZE];


/*===========================================================================*/
static void printfaddr13(uint8_t *addr1, uint8_t *addr2, uint8_t *addr3, char *info)
{

printf("%s %d ", info, mysequencenr);
for(int c = 0; c < 6; c++)
	printf("%02x", addr1[c]);
printf(" ");
for(int c = 0; c < 6; c++)
	printf("%02x", addr2[c]);
printf(" ");
for(int c = 0; c < 6; c++)
	printf("%02x", addr3[c]);
printf("\n");
return;
}

/*===========================================================================*/
/*===========================================================================*/
static void send_broadcastbeacon()
{
int retw;
mac_t *macf;
static capap_t *capap;

const uint8_t broadcastbeacondata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0d,
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00, 
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};
#define BROADCASTBEACON_SIZE sizeof(broadcastbeacondata)

uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1];

if(requestflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_BEACON;
memcpy(macf->addr1, &mac_broadcast, 6);
memcpy(macf->addr2, &mac_myap, 6);
memcpy(macf->addr3, &mac_myap, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0x1312;
capap->capapinfo = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &broadcastbeacondata, BROADCASTBEACON_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x0e] = channelscanlist[cpa];
retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_undirected_proberequest()
{
int retw;
mac_t *macf;

const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00, 0x01, 0x04, 0x02, 0x04, 0x0b, 0x16,
0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
0x03, 0x01, 0x02,
0x2d, 0x1a, 0x2c, 0x01, 0x03, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x08, 0x00, 0x00, 0x00
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1];

if(requestflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macf->addr1, &mac_broadcast, 6);
memcpy(macf->addr2, &mac_mysta, 6);
memcpy(macf->addr3, &mac_broadcast, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +0x14] = channelscanlist[cpa];
retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
void writemacap()
{
macessidlist_t *zeiger;
int c;

zeiger = macapessidliste;
for(c = 0; c < MACAPESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->addr, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, mac_ptr->addr2, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return;
		}
	zeiger++;
	}

zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->addr, mac_ptr->addr2, 6);
zeiger->essid_len = essid_tag->len;
memset(zeiger->essid, 0, 6);
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
qsort(macapessidliste, MACAPESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
void writemacsta()
{
macessidlist_t *zeiger;
int c;

zeiger = macstaessidliste;
for(c = 0; c < MACSTAESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->addr, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, mac_ptr->addr2, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return;
		}
	zeiger++;
	}

zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->addr, mac_ptr->addr2, 6);
zeiger->essid_len = essid_tag->len;
memset(zeiger->essid, 0, 6);
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
qsort(macstaessidliste, MACSTAESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
ietag_t *getessidtag(uint8_t taglen, uint8_t *tagdata)
{
ietag_t *tagl;
tagl = (ietag_t*)tagdata;

while(0 < taglen)
	{
	if(tagl->id == TAG_SSID)
		{
		if((tagl->len == 0) || (tagl->len > 32))
			{
			return NULL;
			}
		if(tagl->data[0] == 0)
			{
			return NULL;
			}
		return tagl;
		}
	tagl = (ietag_t*)((uint8_t*)tagl +tagl->len +IETAG_SIZE);
	taglen -= tagl->len;
	}
return NULL;
}
/*===========================================================================*/
/*===========================================================================*/
void handle_beacon()
{

essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESAP_SIZE);



if(essid_tag != NULL)
	{
	writemacap();
	}
return;
}
/*===========================================================================*/
void handle_directedproberequest()
{
essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM, packet_ptr +MAC_SIZE_NORM);

//printfaddr13(mac_ptr->addr1, mac_ptr->addr2, mac_ptr->addr3, "ui-probe");



if(essid_tag != NULL)
	{
	writemacsta();
	}
return;
}
/*===========================================================================*/
void handle_undirectedproberequest()
{
essid_tag = (ietag_t*)getessidtag(caplen-MAC_SIZE_NORM, packet_ptr +MAC_SIZE_NORM);




if(essid_tag != NULL)
	{
	writemacsta();
	}
return;
}
/*===========================================================================*/
void handle_proberesponse()
{
essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESAP_SIZE);



if(essid_tag != NULL)
	{
	writemacap();
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
if(fd_socket > 0)
	{
	close(fd_socket);
	}
if(fd_pcap > 0)
	{
	close(fd_pcap);
	}
if(fd_ippcap > 0)
	{
	close(fd_ippcap);
	}

free(macstaessidliste);

printf("\nterminated...\e[?25h\n");
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		printf("can't power off\n");
	}
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
#ifdef DOGPIOSUPPORT
static void *rpiflashthread()
{
while(1)
	{
	digitalWrite(0, HIGH);
	delay (25);
	digitalWrite(0, LOW);
	delay (25);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		wantstopflag = true;
		}
	sleep(5);
	}
return NULL;
}
#endif
/*===========================================================================*/
static bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.e = 0;
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[cpa];
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) == -1)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static void *channelswitchthread()
{
while(1)
	{
	sleep(staytime);
	channelsetflag = true;
	}
return NULL;
}
/*===========================================================================*/
static void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	wantstopflag = true;
	}
return;
}
/*===========================================================================*/
static void processpackets()
{
rth_t *rth;
fcs_t *fcs;
uint32_t crc;
unsigned long long int packetcount = 0;
int fdnum;
fd_set readfds;

pkh = (pcaprec_hdr_t*)packetin;
printf("\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"INTERFACE: %s\n"
	"MAC_AP...: %06x%06x (rogue access point)\n"
	"MAC_STA..: %06x%06x (rogue client)\n"
	"INFO.....: cha=%d, rcv=%llu, err=%d\r",
	interfacename, myouiap, mynicap, myouista, mynicsta, channelscanlist[cpa], packetcount, errorcount);
set_channel();
send_broadcastbeacon();
send_undirected_proberequest();
while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelsetflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == false)
			{
			errorcount++;
			}
		if(wantstatusflag == true)
			{
			printf("INFO.....: cha=%d, rcv=%llu, err=%d\r", channelscanlist[cpa], packetcount, errorcount);
			}
		channelsetflag = false;
		send_broadcastbeacon();
		send_undirected_proberequest();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	caplen = read(fd_socket, &packetin[PCAPREC_SIZE], PCAP_SNAPLEN +PCAPREC_SIZE);
	if(fdnum == -1)
		{
		errorcause = -1;
		globalclose();
		}
	if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
		{
		errorcount++;
		continue;
		}
	if(fdnum == 0)
		{
		}
	if(caplen <= 0)
		{
		errorcause = -1;
		globalclose();
		}
	if(caplen < (int)(RTH_SIZE +MAC_SIZE_ACK))
		{
		continue;
		}
	packetcount++;
	pkh->ts_sec = tv.tv_sec;
	pkh->ts_usec = tv.tv_usec;
	pkh->incl_len = caplen;
	pkh->orig_len = caplen;
	packet_ptr = &packetin[PCAPREC_SIZE];
	rth = (rth_t*)packet_ptr;
	#ifdef BIG_ENDIAN_HOST
	rth->it_len	= byte_swap_16(rth->it_len);
	rth->it_present	= byte_swap_32(rth->it_present);
	#endif
	packet_ptr += rth->it_len;
	caplen -= rth->it_len;
	fcs = (fcs_t*)(packet_ptr +caplen -4);
	#ifdef BIG_ENDIAN_HOST
	fcs->fcs	= byte_swap_32(fcs->fcs);
	#endif
	crc = fcscrc32check(packet_ptr, caplen -4);
	if(crc == fcs->fcs)
		{
		caplen -= 4;
		}
	mac_ptr = (mac_t*)packet_ptr;
	if((mac_ptr->from_ds == 1) && (mac_ptr->to_ds == 1))
		{
		continue;
		}
	if(mac_ptr->type == IEEE80211_FTYPE_MGMT)
		{
		if(mac_ptr->subtype == IEEE80211_STYPE_BEACON)
			{
			if(memcmp(&mac_myap, mac_ptr->addr2, 6) == 0)
				{
				continue;
				}
			handle_beacon();
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_PROBE_REQ)
			{
			if(memcmp(&mac_mysta, mac_ptr->addr2, 6) == 0)
				{
				continue;
				}
			if(memcmp(&mac_broadcast, mac_ptr->addr1, 6) == 0)
				{
				handle_undirectedproberequest();
				continue;
				}
			else
				{
				handle_directedproberequest();
				continue;
				}
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			handle_proberesponse();
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_AUTH)
			{ 



			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_ASSOC_REQ)
			{ 


			write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_ASSOC_RESP)
			{ 


			write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_REASSOC_REQ)
			{ 


			write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_REASSOC_RESP)
			{ 


			write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE);
			continue;
			}
		continue;
		}
	else if(mac_ptr->type == IEEE80211_FTYPE_CTL)
		{
		if(IEEE80211_STYPE_ACK)
			{



			continue;
			}
		continue;
		}
	else if (mac_ptr->type == IEEE80211_FTYPE_DATA)
		{
		if(mac_ptr->subtype == IEEE80211_STYPE_NULLFUNC)
			{



			continue;
			}
		else if((mac_ptr->subtype == IEEE80211_STYPE_DATA) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFACK) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFPOLL) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFACKPOLL))
			{



			continue;
			}
		else if((mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFACK) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFPOLL) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFACKPOLL))
			{



			continue;
			}
		}
	}
return;
}
/*===========================================================================*/
static bool opensocket()
{
struct ifreq ifr;
struct sockaddr_ll ll;
const int protocol = ETH_P_ALL;
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(protocol))) < 0)
	{
	perror( "socket failed (do you have root priviledges?)" );
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ);
if (ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0)
	{
	perror("ioctl[SIOCGIFINDEX]");
	close(fd_socket);
	return false;
	}

memset(&ll, 0, sizeof(ll));
ll.sll_family = AF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(protocol);
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0)
	{
	perror("bind[AF_PACKET]");
	close(fd_socket);
	return false;
	}
return true;
}
/*===========================================================================*/
static bool globalinit()
{
int c;
static struct stat statinfo;
int ret;
pthread_t thread1;
#ifdef DOGPIOSUPPORT
static int c;
pthread_t thread2;
#endif

static char newpcapoutname[PATH_MAX +2];

myouiap = myvendorap[rand() % ((MYVENDORAP_SIZE /sizeof(int)))];
mynicap = rand() & 0xffffff;
mac_myap[5] = mynicap & 0xff;
mac_myap[4] = (mynicap >> 8) & 0xff;
mac_myap[3] = (mynicap >> 16) & 0xff;
mac_myap[2] = myouiap & 0xff;
mac_myap[1] = (myouiap >> 8) & 0xff;
mac_myap[0] = (myouiap >> 16) & 0xff;
myouista = myvendorsta[rand() % ((MYVENDORSTA_SIZE /sizeof(int)))];
mynicsta = rand() & 0xffffff;
mac_mysta[5] = mynicsta & 0xff;
mac_mysta[4] = (mynicsta >> 8) & 0xff;
mac_mysta[3] = (mynicsta >> 16) & 0xff;
mac_mysta[2] = myouista & 0xff;
mac_mysta[1] = (myouista >> 8) & 0xff;
mac_mysta[0] = (myouista >> 16) & 0xff;


if(pcapoutname != NULL)
	{
	c = 0;
	strcpy(newpcapoutname, pcapoutname);
	while(stat(newpcapoutname, &statinfo) == 0)
		{
		snprintf(newpcapoutname, PATH_MAX, "%s-%d.pcap", pcapoutname, c);
		c++;
		}
	fd_pcap = hcxopenpcapdump(newpcapoutname);
	if(fd_pcap <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", newpcapoutname);
		return false;
		}
	}

if(ippcapoutname != NULL)
	{
	c = 0;
	strcpy(newpcapoutname, ippcapoutname);
	while(stat(newpcapoutname, &statinfo) == 0)
		{
		snprintf(newpcapoutname, PATH_MAX, "%s-%d.pcap", ippcapoutname, c);
		c++;
		}
	fd_ippcap = hcxopenpcapdump(newpcapoutname);
	if(fd_ippcap <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", newpcapoutname);
		return false;
		}
	}
ret = pthread_create(&thread1, NULL, &channelswitchthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}

#ifdef DOGPIOSUPPORT
ret = pthread_create(&thread2, NULL, &rpiflashthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}
if(wiringPiSetup() == -1)
	{
	puts ("wiringPi failed!");
	return false;
	}
pinMode(0, OUTPUT);
pinMode(7, INPUT);
for (c = 0; c < 5; c++)
	{
	digitalWrite(0 , HIGH);
	delay (200);
	digitalWrite(0, LOW);
	delay (200);
	}
#endif

if((macstaessidliste = calloc((MACSTAESSIDLISTZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}
if((macapessidliste = calloc((MACAPESSIDLISTZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

tvfd.tv_sec = 0;
tvfd.tv_usec = 0;

signal(SIGINT, programmende);

return true;
}
/*===========================================================================*/
static bool ischannelindefaultlist(int userchannel)
{
int cpd = 0;
while(channeldefaultlist[cpd] != 0)
	{
	if(userchannel == channeldefaultlist[cpd])
		{
		return true;
		}
	cpd++;
	}
return false;
}
/*===========================================================================*/
static bool processuserscanlist(char *optarglist)
{
char *ptr;
static char *userscanlist;

userscanlist = strdupa(optarglist);
cpa = 0;
ptr = strtok(userscanlist, ",");
while(ptr != NULL)
	{
	channelscanlist[cpa] = atoi(ptr);
	if(ischannelindefaultlist(channelscanlist[cpa]) == false)
		{
		return false;
		}
	ptr = strtok(NULL, ",");
	cpa++;
	if(cpa > 127)
		{
		return false;
		}
	}
channelscanlist[cpa] = 0;
cpa = 0;
return true;
}
/*===========================================================================*/
static bool check_wlaninterface(const char* ifname)
{
int fd_info;
struct iwreq fpwrq;
memset(&fpwrq, 0, sizeof(fpwrq));
strncpy(fpwrq.ifr_name, ifname, IFNAMSIZ);

if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

if (ioctl(fd_info, SIOCGIWNAME, &fpwrq) != -1)
	{
	return true;
	}
close(fd_info);
return false;
}
/*===========================================================================*/
static void show_wlaninterfaces()
{
struct ifaddrs *ifaddr=NULL;
struct ifaddrs *ifa = NULL;
struct sockaddr_ll *sfda;
static int i = 0;

if(getifaddrs(&ifaddr) == -1)
	{
	perror("getifaddrs failed ");
	}
else
	{
	printf("suitable wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			if(check_wlaninterface(ifa->ifa_name) == true)
				{
				sfda = (struct sockaddr_ll*)ifa->ifa_addr;
				printf("INTERFACE: %s [", ifa->ifa_name);
				for (i=0; i < sfda->sll_halen; i++)
					{
					printf("%02x", (sfda->sll_addr[i]));
					}
				printf("]\n");
				}
			}
		}
	freeifaddrs(ifaddr);
	}
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <interface> : interface\n"
	"-o <dump file> : output file in pcapformat including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-O <dump file> : ip based traffic output file in pcapformat including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-c <digit>     : set channel (default = channel 1) or comma separted channel scanlist (1,2,3,...)\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"               : default = 5 seconds\n"
	"-T <maxerrors> : terminate after <x> maximal errors\n"
	"               : default: 1000000\n"
	"-D             : do not transmit deauthentications or disassociations\n"
	"-R             : do not transmit requests\n"
	"-A             : do not respond to requests from clients\n"
	"-P             : enable poweroff\n"
	"-s             : enable status messages\n"
	"-I             : show suitable wlan interfaces and quit\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;

srand(time(NULL));
setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:O:c:t:T:DRAsIhv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		interfacename = optarg;
		if(interfacename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		pcapoutname = optarg;
		break;

		case 'O':
		ippcapoutname = optarg;
		break;

		case 'c':
		if(processuserscanlist(optarg) == false)
			{
			fprintf(stderr, "unknown channel selected\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime <= 1)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1\n");
			staytime = TIME_INTERVAL;
			}
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'D':
		deauthflag = true;
		break;

		case 'R':
		requestflag = true;
		break;

		case 'A':
		respondflag = true;
		break;

		case 'P':
		poweroffflag = true;
		break;

		case 's':
		wantstatusflag = true;
		break;

		case 'I':
		showinterfaces = true;
		break;

		case 'h':
		usage(basename(argv[0]));

		case 'v':
		version(basename(argv[0]));

		default:
		usageerror(basename(argv[0]));
		}
	}

if(showinterfaces == true)
	{
	show_wlaninterfaces();
	return EXIT_SUCCESS;
	}

if(interfacename == NULL)
	{
	fprintf(stderr, "no interface selected\n");
	exit(EXIT_FAILURE);
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(opensocket() == false)
	{
	fprintf(stderr, "failed to init socket\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	fprintf(stderr, "failed to init globals\n");
	exit(EXIT_FAILURE);
	}

processpackets(); 

return EXIT_SUCCESS;
}
/*===========================================================================*/
