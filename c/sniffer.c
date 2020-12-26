#define stdin 0
#define stdout 1
#define stderr 2

#define print(literal)    write(stdout, literal, sizeof(literal)-1)
#define error(literal)    write(stderr, literal, sizeof(literal)-1)

typedef unsigned short int uint16;
typedef unsigned long int uint32;

#define BIGLITTLESWAP16(A) (((uint16) (A) & 0xff00) >> 8) | (((uint16) (A) & 0X00FF) << 8)
#define BIGLITTLESWAP32(A) (((uint32) (A) & 0xff000000) >> 24) | (((uint32) (A) & 0x00ff0000) >> 8) | (((uint32) (A) & 0x0000ff00) << 8) | (((uint32) (A) & 0x000000ff) << 24)

#define htons(a) BIGLITTLESWAP16(a)
#define htonl(a) BIGLITTLESWAP32(a)

// ASM hooks
extern int write(int fd, const char *buf, unsigned int count);
extern int read(int fd, char *buf, unsigned int count);
extern void exit(int code);
extern int client_setup(void);
extern int raw_socket_setup(char *device, unsigned int length);

struct ethernet {
	char dst[6];
	char src[6];
	unsigned short type;
}__attribute__((packed));

struct ethernet_8021q {
	char dst[6];
	char src[6];
	unsigned short TPID;
	unsigned short TCI;
	unsigned short type;
}__attribute__((packed));

struct ipv4 {
	char version:4, ihl:4;
	char tos;
	unsigned short len;
	unsigned short id;
	unsigned short flags:3, frag_offset:13;
	char ttl;
	char proto;
	unsigned short csum;
	unsigned int saddr;
	unsigned int daddr;
}__attribute__((packed));

struct tcp {
	unsigned short sport;
	unsigned short dport;
	unsigned int seq_num; 
	unsigned int ack_num;
	unsigned char reserved:4, offset:4;
	unsigned char flags;
	unsigned short win;
	unsigned short chksum;
	unsigned short urgptr;
}__attribute__((packed));

struct eth_ip_tcp {
	struct ethernet eth;
	struct ipv4 ip;
	struct tcp tcp;
}__attribute__((packed));;

// Little hack to print out struct size at compile time in a warning
// https://stackoverflow.com/questions/20979565/how-can-i-print-the-result-of-sizeof-at-compile-time-in-c
//char (*__kaboom)[sizeof(struct ipv4)] = 1;
//void kaboom_print( void )
//{
//    printf( "%d", __kaboom );
//}

void write_int(int fd, int n)
{ 
	if( n > 9 ){
		int a = n / 10;
		n -= 10 * a;
		write_int(fd, a);
	}
	char digit = '0'+n;
	write(fd, &digit, 1);
}

// Return 1 if accept return 0 if drop
int passes_filter(char *packet)
{
	struct eth_ip_tcp *p = (struct eth_ip_tcp*) packet;
	int ret = 1;

	// Realigntype indicates it is 802.1q
	// Note this breaks mac adressing but that is not currently used
	if(htons(p->eth.type) == 0x8100)			// 802.1q
		p = (struct eth_ip_tcp*) (packet + 4);
	if(htons(p->eth.type) == 0x800) { 			// IPv4
		//print("type: ip ");
		if(p->ip.proto == 6 ) {   			// TCP
			//print("tcp ");
			//write_int(stdout, htons(p->tcp.sport));
			//print("->");
			//write_int(stdout, htons(p->tcp.dport));
			if(htons(p->tcp.sport) == 4444)		// Sniffer tx dport response
				ret=0;
			else if(htons(p->tcp.dport) == 4444)	// Sniffer tx dport
				ret=0;
			else if(htons(p->tcp.sport) == 22)	// ssh dport response
				ret=0;
			else if(htons(p->tcp.dport) == 22)	// ssh dport
				ret=0;
		}
	}
	//print("\n");

//	if(!ret)
//		print("dropping\n");

	return ret;
}

void _start(void)
{
	static char buffer[1600];

	int tcp_socket = client_setup();
	int raw_socket = raw_socket_setup("br0", 3);

	print("Starting Sniffer\n");

	while(1) {
		// Receive Packet
		int nbytes = read(raw_socket, buffer, sizeof(buffer));
		// Filter out TCP packets from this program
		// Transmit Packet out TCP connection
		if(passes_filter(buffer)) {
			//print("Transmitting packet\n");
			write(tcp_socket, buffer, nbytes);
			// Send delimeter
			write(tcp_socket, "-DELIM-", 7);
		}
	}

	exit(0);
}
