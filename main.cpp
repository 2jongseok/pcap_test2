#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>

#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define IPPROTO_TCP    0x06        /* TCP protocol */

struct	ethhdr{
    uint8_t	ether_dhost[6];
    uint8_t	ether_shost[6];
    uint16_t	ether_type;
};

struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t	ip_hl:4,		/* header length */
    ip_v:4;			/* version */

#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	ip_v:4,			/* version */
    ip_hl:4;		/* header length */

#endif
    uint8_t	ip_tos;			/* type of service */
    uint16_t	ip_len;			/* total length */
    uint16_t	ip_id;			/* identification */
    uint16_t	ip_off;			/* fragment offset field */

    uint8_t	ip_ttl;			/* time to live */
    uint8_t	ip_p;			/* protocol */
    uint16_t	ip_sum;			/* checksum */
    uint8_t  ip_src[4];
    uint8_t  ip_dst[4];         /* source and dest address */
};

struct tcphdr {
    uint16_t	th_sport;		/* source port */
    uint16_t	th_dport;		/* destination port */
    uint64_t	th_seq;			/* sequence number */
    uint64_t	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t    	th_x2:4,		/* (unused) */
    th_off:4;                   	/* data offset */
#endif 
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	th_off:4,		/* data offset */
    th_x2:4;		/* (unused) */
};  
    struct ethhdr * eth
    struct iphdr * ip
    sturct tcphdr * tcp
    
    
    void dump(const u_char * p, int len){
     
        eth = (struct ethhdr *)p;
        printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      
        printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
      
        
        if (ntohs(eth->prt_type) == ETHERTYPE_IP){
            p = p +  sizeof(struct ethhdr);
            ip = (struct ip_header *)p;
            printf("Src IP : %d.%d.%d.%d\n", ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3] );
           
            printf("Dst IP : %d.%d.%d.%d\n", ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);
            
           
            if (ip->protocol == IPPROTO_TCP){
                p = p + (ip->ip_hl) * 4;
                tcp = (struct tcp_header *)p;
                printf("Src Port : %d\n", ntohs(tcp->th_sport));
                printf("Dst Port : %d\n", ntohs(tcp->th_dport));
                
                p = p + (tcp->th_off) * 4;
                
                int iplen = (ip->ip_hl) * 4;
                int tcplen = (tcp->th_off) * 4;
                int totallen = ip->ip_len;
                
                int datalen = totallen - iplen - tcplen;
                
                if (datalen > 32){
                    for (int i = 0; i < 32; i++){
                        printf("%02X ", *p);
                        if ((i & 0x0f) == 0x0f){
                            printf("\n");
                        }
                     p++;
                    }
                    printf("...\n");
                }
               
                else{
                   for (int i = 0; i < datalen; i++){
                         printf("%02X ", *p);
                        if ((i & 0x0f) == 0x0f){
                            printf("\n");
                        }
                     p++;
                    }
                    printf("\n");
                }
            }
        }
    }


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char * argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr * header;
    const u_char * packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}

