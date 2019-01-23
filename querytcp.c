/*
TCP query version of queryperf
querytcp.c
				fujiwara@jprs.co.jp
				2009.08.12
				version 0.4

queryperf for tcp query

This program measures DNS server performance of TCP query.

o Running environment:
	Development environment:
		FreeBSD, Linux
		#MacOS X 10.3.4

o How to make:
    FreeBSD, Linux: cc -Wall -O2 -g -lm -o querytcp querytcp.c
    #MacOS X: cc -Wall -O2 -g -lm -lresolv -o querytcp querytcp.c

o changes

  2009/8/12: Remove use of res_mkquery
  2012/10/16: fixed a typo, EDNS0 works.
*/

#define FD_SETSIZE 16384

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>
#include <err.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <math.h>
#ifndef NO_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef __APPLE__
#include <nameser8_compat.h>
#endif

#ifndef ns_t_soa
#define	ns_t_soa	T_SOA
#endif
#ifndef ns_t_ns
#define	ns_t_ns		T_NS
#endif
#ifndef ns_c_in
#define	ns_c_in		C_IN
#endif

#ifdef NOINET6
#undef AF_INET6
#endif

#define	Global

#ifndef PACKETSZ
#define	PACKETSZ	512
#endif

/* debug.c */
void hexdump(char *title, unsigned char *memory, int len)
{
	printf("[ %s ", title);
	while (len-- > 0)
		printf("%02x ", *memory++);
	printf("]\n");
}

#define Xmalloc(size)	Xrealloc(NULL, size)

void *Xrealloc(void *p, int size)
{
	int sz;

	sz = (size > 0) ? size : -size;
	if (p == NULL) {
		p = malloc(sz);
	} else {
		p = realloc(p, sz);
	}
	if (p == NULL) {
		char buf[100];
		snprintf(buf, sizeof buf, "size=%d", size);
		perror(buf);
		exit(1);
	}
	if (size < 0)
		memset(p, 0, sz);
	return p;
}

/*
  NULL ... returns NULL
 */

char *Xstrdup(char *p)
{
	char *q;
	int len;

	if (p == NULL)
		return NULL;
	len = strlen(p) + 1;
	q = Xmalloc(len);
	strncpy(q, p, len);
	return q;
}


typedef int64_t timediff_t;

/* packet buffer */
static struct timeval current;
static struct timeval start, send_finished;;
static fd_set fdset0r, fdset0w;
static int nfds;
static struct sockaddr_storage remote;
static int remote_len;
static int finished = 0;
static timediff_t Timeout = 10*1000000LL;
unsigned short counter = 0;

#define	UpdateCurrentTime		gettimeofday(&current, NULL)

#define	RECVBUFSIZ	65537
#define	SENDBUFSIZ	512

struct dnsheader  {
  unsigned short id;
  unsigned char flag1, flag2;
  unsigned short qdcount, ancount, nscount, arcount;
};

/*
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
	
struct queries {
	struct tcpdns {
		u_short len;
		u_char dnsdata[SENDBUFSIZ];
	} send;
	u_char recvbuf[RECVBUFSIZ];
	int sendlen;
	int state;
	int fd;
	int rpos;
	int wpos;
	int no;
	struct timeval sent; /* long tv_sec, long tv_usec */
};

struct queries *Queries;

#define	NQUERY 16384

#define	State_None	0
#define	State_WaitForSend	1
#define	State_WaitForRecv	2

#define DATA_VERSION  0
#define DATA_RANDOM   1
#define DATA_FROMFILE 2
#define DATA_FROMSTDIN 3

/* input */
char *ServerName = "127.0.0.1";
char *ServerPort = "domain";
int family = PF_UNSPEC;
int data_mode = DATA_VERSION;
char *datafile = NULL;
FILE *data_fp = NULL;
char *basedom = NULL;

int TimeLimit = 20;
int EDNS0 = 0;
int DNSSEC = 0;
int recursion = 0;
int datafileloop = 0;
int verbose = 0;
int nQueries = 120;
int printrcode = 1;
int reuse_session = 0;
char *rcodestr[]= {
	"NOERROR", "FormatError", "ServerFailure", "NameError",
	"NotImplemented", "Reused", "RCODE06", "RCODE07",
	"RCODE08", "RCODE09", "RCODE10", "RCODE11",
	"RCODE12", "RCODE13", "RCODE14", "RCODE15",
};

timediff_t timediff(struct timeval *a, struct timeval *b) /* u sec */
{
	return (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec);
}

#define	TIMEOUTERROR	-1
#define	SENDERROR	-2
#define	RECVERROR	-3
#define	SOCKETERROR	-4
#define	ERRZEROREAD	-5

uint64_t countrcode[16];
uint64_t counterrno[100];
uint64_t response_size_sum = 0;
uint64_t response_size_sum2 = 0;
uint64_t countanswers = 0;
uint64_t countqueries = 0;
uint64_t countzeroread = 0;
uint64_t countsenderror = 0;
uint64_t countrecverror = 0;
uint64_t countsocketerror = 0;
uint64_t counttimeout = 0;
uint64_t counterror = 0;
uint64_t count_socket = 0;
uint64_t count_send = 0;
uint64_t count_read = 0;
uint64_t count_close = 0;
uint64_t count_select = 0;

int response_size_min = 0;
int response_size_max = 0;



void register_response(struct queries *q, int timeout, char *note)
{
	u_char *p;
	int size;
	int rcode;
	int id;
	struct dnsheader *h;

	h = (struct dnsheader *)q->send.dnsdata;
	id = ntohs(h->id);
	if (note == NULL)
		note = "";
	countqueries++;
	if (timeout < 0) {
		if (errno >= 0 && errno < 100)
			counterrno[errno]++;
	}
	switch (timeout) {
	case ERRZEROREAD:
		countzeroread++;
		if (verbose)
			printf("recv response id=%d zeroread\n", id);
		break;
	case SOCKETERROR:
		countsocketerror++;
		break;
	case TIMEOUTERROR:
		counttimeout++;
		if (verbose)
			printf("recv timeout id=%d %ld usec\n", id, timediff(&current, &q->sent));
		break;
	case SENDERROR:
		countsenderror++;
		break;
	case RECVERROR:
		countrecverror++;
		break;
	default:
		if (timeout >= 0) {
			p = q->recvbuf;
			NS_GET16(size, p);
			response_size_sum += size;
			response_size_sum2 += size * size;
			if (response_size_min == 0 || response_size_min > size)
				response_size_min = size;
			if (response_size_max == 0 || response_size_max < size)
				response_size_max = size;
			rcode = p[3] & 0x0f;
			countrcode[rcode]++;
			countanswers++;
			if (verbose)
				printf("recv response id=%d rcode=%d size=%d rtt=%d\n", id, rcode, size, timeout);
		}
		break;
	}
#ifdef DEBUG
	printf("%ld.%03ld no=%d fd=%d %d %s\n", q->sent.tv_sec, q->sent.tv_usec/1000, q->no, q->fd, timeout, note); */
	fflush(stdout);
#endif
}

void output()
{
	double response_size_average, response_size_variance, et;

	et = ((double)timediff(&current, &start))/1000000.0;

	counterror = countzeroread + countsocketerror + countsenderror + countrecverror + counttimeout;
	printf("elapsed time: %.3f\n", et);
	printf("tcp qps: %.3f\n", (double)countanswers/et);
	printf("sent: %ld\n", countqueries);
	printf("answer: %lu  %3.1f%%\n", countanswers,
		 (double)((double)countanswers/(double)countqueries*100.0));
	printf("error: %ld  %3.1f%%\n", counterror,
		 (double)((double)counterror/(double)countqueries*100.0));
	printf("zeroread: %ld  %3.1f%%\n", countzeroread,
		 (double)((double)countzeroread/(double)countqueries*100.0));
	printf("socketerror: %ld  %3.1f%%\n", countsocketerror,
		 (double)((double)countsocketerror/(double)countqueries*100.0));
	printf("senderror: %ld  %3.1f%%\n", countsenderror,
		 (double)((double)countsenderror/(double)countqueries*100.0));
	printf("recverror: %ld  %3.1f%%\n", countrecverror,
		 (double)((double)countrecverror/(double)countqueries*100.0));
	printf("timeout: %ld  %3.1f%%\n", counttimeout,
		 (double)((double)counttimeout/(double)countqueries*100.0));
	response_size_average = (double)response_size_sum/countanswers;
	response_size_variance = (double)response_size_sum2 / countanswers
		- response_size_average * response_size_average;
	printf("response size:        %d/%.3f/%d/%.3f bytes\n", response_size_min, response_size_average, response_size_max, sqrt(response_size_variance));
	if (printrcode) {
		int i;
		for (i = 0; i < 16; i++) {
			if (countrcode[i] != 0) {
				printf("%s %lu %5.1f\n", rcodestr[i], countrcode[i], ((double)countrcode[i])/((double)countanswers)*100.0);
			}
		}
		for (i = 0; i < 100; i++) {
			if (counterrno[i] != 0) {
				printf("errno %d %lu %5.1f\n", i, counterrno[i], ((double)counterrno[i])/((double)countqueries)*100.0);
			}
		}
	}
	printf("nfds=%d\n", nfds);
	printf("count_socket=%lu\n", count_socket);
	printf("count_close=%lu\n", count_close);
	printf("count_send=%lu\n", count_send);
	printf("count_read=%lu\n", count_read);
	printf("count_select=%lu\n", count_select);
}

void tcp_close(struct queries *q)
{
#ifdef DEBUG
printf("tcp_close no=%d fd=%d\n", q->no, q->fd);
#endif
	if (q->fd >= 0) {
		close(q->fd);
		count_close++;
		FD_CLR(q->fd, &fdset0r);
		FD_CLR(q->fd, &fdset0w);
	}
	q->state = State_None;
	q->fd = -1;
}

void tcp_send(struct queries *q)
{
	int len;

	len = send(q->fd, &q->send, q->sendlen, MSG_NOSIGNAL);
	count_send++;
#ifdef DEBUG
printf("tcp_send no=%d fd=%d %d:%d:%d\n", q->no, q->fd, len, q->wpos, q->sendlen);
#endif
	if (len < 0) {
		if (errno == ENOTCONN) {
printf("tcp_send no=%d fd=%d ENOTCONN return\n", q->no, q->fd);
			return;
		}
		register_response(q, SENDERROR, "tcp_send1");
		tcp_close(q);
		return;
	}
	if (len != q->sendlen) {
		register_response(q, SENDERROR, "tcp_send:send2");
		tcp_close(q);
		return;
	}
	FD_CLR(q->fd, &fdset0w);
	FD_SET(q->fd, &fdset0r);
}

struct typecodes {
	char *name;
	int code;
} typecodes[] = {
	{ "A", ns_t_a },
	{ "NS", ns_t_ns },
	{ "SOA", ns_t_soa },
	{ "PTR", ns_t_ptr },
	{ "HINFO", ns_t_hinfo },
	{ "MX", ns_t_mx },
	{ "TXT", ns_t_txt },
	{ "SIG", ns_t_sig },
	{ "KEY", ns_t_key },
	{ "AAAA", ns_t_aaaa },
	{ "NXT", ns_t_nxt },
	{ "SRV", ns_t_srv },
	{ "NAPTR", ns_t_naptr },
	{ NULL, -1 },
};

int stringtodname(char *qname, u_char *buff, u_char *lim)
{
	u_char *p, *s, *t;
	int count, total;

	t = (u_char *)qname;
	p = buff;
	total = 0;
	for ( ;; ) {
		s = p++;
		count = 0;
		if (p >= lim) return -1;
		while (*t != 0 && *t != '.')
			if (p < lim) {
				*p++ = *t++;
				count++;
			} else
				return -1;
		*s = count;
		if (count == 0)
			break;
		if (count > 63)
			return -1;
		total += count + 1;
		if (*t == '.') t++;
	}
	if (total > 250 || !(*t == 0 || (*t == '.' && t[1] == 0)))
		return -1;
	return p - buff;
}

void send_query_error(char *mesg)
{
	err(1, "Packet size exceed: %s", mesg);
}

void send_query(struct queries *q)
{
	u_char *p, *lim;
	char *qname;
	int qclass;
	int qtype;
	int tmp;
	char c1;
	char c2;
	char c3;
	u_int64_t r;
	struct dnsheader *h;
	struct typecodes *t = typecodes;
	u_char buff[512];
	static char sep[] = "\n\t ";
	static int lineno = 0;
	char qnamebuf[257];

	/*
		SEND E[send_packet_pos]
	 */
	if (q->state != State_None) {
		register_response(q, TIMEOUTERROR, "send_query");
		tcp_close(q);
	}
	switch(data_mode) {
	default:
	case DATA_VERSION:
		qname = "version.bind";
		qclass = ns_c_chaos;
		qtype = ns_t_txt;
		break;
	case DATA_RANDOM:
		r = random();
		qclass = ns_c_in;
		qtype = (r & 1) ? ns_t_a : ns_t_aaaa;
		r = r / 2;
		c1 = 'a' + r % 26;
		r = r / 26;
		c2 = 'a' + r % 26;
		r = r / 26;
		c3 = 'a' + r % 26;
		r = r / 26;
		snprintf(qnamebuf, sizeof qnamebuf, "%c%c%c%lu.%s", c1, c2, c3, r, basedom);
		qname = qnamebuf;
		break;
	case DATA_FROMSTDIN:
	case DATA_FROMFILE:
		do {
			if (fgets((char *)buff, sizeof buff, data_fp) == NULL) {
				if (datafileloop == 1 || data_mode == DATA_FROMSTDIN) {
					finished = 1;
					fclose(data_fp);
					data_fp = NULL;
					return;
				}
				if (datafileloop > 0)
					datafileloop--;
				rewind(data_fp);
				lineno = 0;
				if (fgets((char *)buff, sizeof buff, data_fp) == NULL)
					err(1, "cannot rewind input file");
			}
			lineno++;
		} while(buff[0] == '#');
		qname = strtok((char *)buff, sep);
		p = (u_char *)strtok(NULL, sep);
		if (p != NULL) {
			while(t->name != NULL) {
				if (!strcasecmp(t->name, (char *)p))
					break;
				t++;
			}
			qtype = t->code;
		} else {
			qtype = ns_t_a;
		}
		if (qname == NULL || qtype < 0)
			err(1, "datafile format error at line %d, qname=%s qtype=%d", lineno, qname, qtype);
		qclass = ns_c_in;
		break;
	}
	h = (struct dnsheader *)&q->send.dnsdata;
	h->id = counter++;
	h->flag1 = recursion ? 1 : 0; /* Query,OP=0,AA=0,TC=0,RD=0/1 */
	h->flag2 = 0;
	h->qdcount = htons(1);
	h->ancount = 0;
	h->nscount = 0;
	h->arcount = 0;
	p = (u_char *)h + sizeof(struct dnsheader);
	lim = (u_char *)h + sizeof(q->send.dnsdata);
	if ((tmp = stringtodname(qname, p, lim)) < 0)
		send_query_error(qname);
	p += tmp;
	*(unsigned short *)p = htons(qtype);
	p += sizeof(unsigned short);
	*(unsigned short *)p = htons(qclass);
	p += sizeof(unsigned short);
	q->sendlen = p - q->send.dnsdata;
	if (EDNS0) {
#define EDNS0size 11
		if (q->sendlen + EDNS0size >= sizeof(q->send.dnsdata))
			send_query_error("ENDS0");
		*p++ = 0; /* . */
		*(unsigned short *)p = htons(ns_t_opt);
		p += 2;
		*(unsigned short *)p = htons(4096);
		p += 2;
		*p++ = 0;
		*p++ = 0;
		*p++ = (DNSSEC == 0) ? 0 : 0x80; /* eflag: DO bit */
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		q->sendlen += EDNS0size;
		p = (u_char *)&q->send.dnsdata;
		h->arcount = htons(1);
	}
	q->send.len = htons(q->sendlen);
	q->sendlen += sizeof(q->send.len);
	q->wpos = 0;
	q->rpos = 0;
	q->sent = current;
	if (verbose > 0) {
		int id = (q->send.dnsdata[0] << 8) | q->send.dnsdata[1];
		printf("sending query(%s,%d,%d) id=%d %d bytes to %s\n", qname, qclass, qtype, id, q->sendlen, ServerName);
	}
	if (q->fd > 0 && reuse_session == 0)
		err(1, "q->fd > 0 but ignored\n");
	if (q->fd <= 0 &&
		(
           count_socket++ < 0
		|| (q->fd = socket(remote.ss_family, SOCK_STREAM, 0)) < 0
		|| (tmp = fcntl(q->fd, F_GETFL, 0)) == -1
	    || fcntl(q->fd, F_SETFL, O_NONBLOCK | tmp) == -1
	    || (connect(q->fd, (struct sockaddr *)&remote, remote_len) < 0 && errno != EINPROGRESS))) { 
		register_response(q, SOCKETERROR, "send_query:socket+fcntl+connect");
		tcp_close(q);
		return;
	}
#ifdef DEBUG
printf("send_query no=%d fd=%d socket|connect\n", q->no, q->fd);
#endif
	q->state = State_WaitForSend;
	FD_SET(q->fd, &fdset0w);
	FD_CLR(q->fd, &fdset0r);
	if (nfds <= q->fd) {
		nfds = q->fd + 1;
	}
	q->sent = current;
}

int UpdateQuery()
{
	int i;
	timediff_t t, min = Timeout;
	struct queries *q;
	int free = 0;

	if (!finished && TimeLimit > 0) {
		if ((t = timediff(&current, &start)) > TimeLimit * 1000000LL) {
			finished = 1;
			send_finished = current;
		}
	}
	for(i = 0; i < nQueries; i++) {
		q = &Queries[i];
		if (q->state != State_None) {
			if ((t = timediff(&current, &q->sent)) > Timeout) {
				/* timeouted */
				register_response(q, TIMEOUTERROR, "UpdateQuery");
				tcp_close(q);
			} else
			if (t < min)
				min = t;
		} else {
			if (!finished)
				send_query(q);
			else
				free++;
		}
	}
	if (free == nQueries)
		min = -1; /* finished */
	return min;
}

char *skipname(char *p)
{
	while(*p > 0 && *p < 0x40) p += *p + 1;
	if (*p == 0)
		return p+1;
	return p+2;
}

#define Hexdump(A,B,C)

void tcp_receive(struct queries *q)
{
	int len, len2;
	timediff_t tmp;
	unsigned char *recvp;

/*printf("tcp_receive %s\n", q->nameserverlabel);*/

	len = read(q->fd, q->recvbuf + q->rpos, len2 = RECVBUFSIZ - q->rpos);
	count_read++;
	if (len < 0) {
		if (errno == EAGAIN)
			return;
		register_response(q, RECVERROR, "tcp_receive:read");
		tcp_close(q);
		return;
	}
	if (len == 0) {
		register_response(q, RECVERROR, "tcp_receive:read");
		tcp_close(q);
		return;
	}
	q->rpos += len;
	if (q->rpos < 2)
		return;
	len2 = (q->recvbuf[0] << 8) || q->recvbuf[1];
	if (q->rpos >= len2 + 2) {
		/* finished */
		recvp = q->recvbuf + 2;
		if (memcmp(recvp, &q->send.dnsdata, 2) == 0) {
			if ((recvp[2] & 1) == 0 /* RA bit */
			  || (recvp[3] & 15) != 0 /* RCODE must be 0 */
			) {
/*
				fprintf(stderr, "WRONG AA=%d RCODE=%d\n",
					((recvp[2]>>2) & 1), recvp[3]&15);
*/
			}
			tmp = timediff(&current, &q->sent);
			register_response(q, tmp, "tcp_receive");
			if (reuse_session) {
				q->state = State_None;
			} else {
				tcp_close(q);
			}
			return;
		} else {
printf("no=%d fd=%d unknown recv %d bytes, len=%d\n", q->no, q->fd, q->rpos, (q->recvbuf[0] << 8)|q->recvbuf[1]);
			hexdump("", q->recvbuf, len);
			/*
			fprintf(stderr, "unknown recv from %s, %d bytes %02x %02x\n", q->nameserverlabel, q->rpos, recvp[0], recvp[1]);
			*/
			tcp_close(q);
		}
	}
}

void query()
{
	fd_set fdsetr, fdsetw;
	struct timeval timeout;
	int min;
	struct queries *q;
	int i, n;
	struct addrinfo hints, *res0;
	int error;

	Queries = Xmalloc(sizeof(Queries[0]) * nQueries);
	memset(&remote, 0, sizeof(remote));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(ServerName, ServerPort, &hints, &res0);
	if (error) {
		errx(1, "%s", gai_strerror(error));
	}
	memcpy(&remote, res0->ai_addr, res0->ai_addrlen);
	remote_len = res0->ai_addrlen;
	memset(&countrcode, 0, sizeof(countrcode));

	res_init();
	_res.options ^= ~RES_RECURSE;
	_res.options |= RES_AAONLY;

	for (i = 0; i < nQueries; i++) {
		Queries[i].state = State_None;
		Queries[i].no = i;
	}

	FD_ZERO(&fdset0r);
	FD_ZERO(&fdset0w);
	nfds = 0;
	UpdateCurrentTime;
	start = current;
	finished = 0;

	for (;;) {
		UpdateCurrentTime;
		if ((min = UpdateQuery()) < 0)
			break;
		timeout.tv_sec = min / 1000000;
		timeout.tv_usec = min % 1000000;
		fdsetr = fdset0r;
		fdsetw = fdset0w;
		n = select(nfds, &fdsetr, &fdsetw, NULL, &timeout);
		count_select++;
		UpdateCurrentTime;
		for(i = 0; i < nQueries; i++) {
			q = &Queries[i];
			if (q->fd < 0 || q->state == State_None)
				continue;
			if (FD_ISSET(q->fd, &fdsetw)) {
				tcp_send(q);
			} else if (FD_ISSET(q->fd, &fdsetr)) {
				tcp_receive(q);
			}
		}
	}
}

void usage()
{
	fprintf(stderr, 
"querytcp {-d datafile|-r domainname|-H} [-s server_addr] [-p port] [-q num_queries] [-t timeout] [l limit] [-4] [-6] [-h]\n"
"  -s IPaddr : sets the server to query [127.0.0.1]\n"
"  -p port   : sets the port on which to query the server [53]\n"
"  -q num    : specifies the maximum number of queries outstanding [120]\n"
"  -t timeout: specifies the timeout for query completion in seconds [10]\n"
"  -l howlong: specifies how a limit for how long to run tests in seconds (no default)\n"
"  -e enable EDNS0\n"
"  -D set DO bit\n"
"  -R set RD bit\n"
"  -u Reuse TCP session\n"
"\n"
"  Query data (Qname, Qtype) from:\n"
"     -d file : input data file / - means from stdin\n"
"     -r name : {random}.name A/AAAA queries\n"
"     -H      : hostname.bind CH TXT\n"
"\n"
"  -h print this usage\n"
);
	exit(1);
}

int main(int argc, char *argv[])
{
	int ch, i;

	while ((ch = getopt(argc, argv, "d:s:p:q:t:l:46euDvhHRhr:")) != -1) {
	switch (ch) {
	case 'q':
		nQueries = atoi(optarg);
		if (nQueries < 1)
			err(1, "-q requires natural number");
		break;
	case 'p':
		ServerPort = Xstrdup(optarg);
		break;
	case 's':
		ServerName = Xstrdup(optarg);
		break;
	case 'd':
		datafile = Xstrdup(optarg);
		if (strcmp(datafile, "-")) {
			data_mode = DATA_FROMSTDIN;
			data_fp = stdin;
		} else {
			data_mode = DATA_FROMFILE;
			if ((data_fp = fopen(datafile, "r")) == NULL)
				err(1, "cannot open %s", optarg);
		}
		break;
	case 'r':
		basedom = Xstrdup(optarg);
		data_mode = DATA_RANDOM;
		break;
	case 'H':
		data_mode = DATA_VERSION;
		break;
	case 't':
		i = atoi(optarg);
		if (i < 1)
			err(1, "-t timeout > 0");
		Timeout = (int64_t)i * 1000000LL;
		break;
	case 'l':
		TimeLimit = atoi(optarg);
		break;
	case '4':
		family = AF_INET;
		break;
	case '6':
		family = AF_INET6;
		break;
	case 'e':
		EDNS0 = 1;
		break;
	case 'D':
		DNSSEC = 1;
		break;
	case 'R':
		recursion = 1;
		break;
	case 'v':
		verbose = 1;
		break;
	case 'c':
		printrcode = 1;
		break;
	case 'u':
		reuse_session = 1;
		break;
	case 'h':
	default:
		usage();
	}
	}
	argc -= optind;
	argv += optind;

	query();
	output();

	return 0;
}
