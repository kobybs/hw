#define TCP_PROTOCOL_CODE 6
#define UDP_PROTOCOL_CODE 17

// linux arphdr doesn't include the mac addresses, therefore we declare a new struct
struct full_arphdr
{
    unsigned short int ar_hrd;                /* Format of hardware address.  */
    unsigned short int ar_pro;                /* Format of protocol address.  */
    unsigned char ar_hln;                /* Length of hardware address.  */
    unsigned char ar_pln;                /* Length of protocol address.  */
    unsigned short int ar_op;                /* ARP opcode (command).  */
    unsigned char __ar_sha[ETH_ALEN];        /* Sender hardware address.  */
    unsigned char __ar_sip[4];                /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];        /* Target hardware address.  */
    unsigned char __ar_tip[4];                /* Target IP address.  */
};

asmlinkage int (*org_netif) (struct sk_buff *skb);

static bool should_filter_ip_packet(struct iphdr *top_iph, struct sk_buff *skb){
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    printk("ttl: %d, protocol: %d, saddr: %d.%d.%d.%d", top_iph->ttl, top_iph->protocol, ((unsigned char*)&top_iph->saddr)[0], ((unsigned char*)&top_iph->saddr)[1], ((unsigned char*)&top_iph->saddr)[2], ((unsigned char*)&top_iph->saddr)[3]);
    if (top_iph->saddr == *(unsigned int *)DROP_SIP) { 
	    return true;
    }

    if (top_iph->protocol == UDP_PROTOCOL_CODE)
    {
        udp_header = udp_hdr(skb);
        if (udp_header != NULL){
            printk("udp ports are (s,d): %d, %d", htons(udp_header->source), htons(udp_header->dest));
            if (htons(udp_header->source) == DROP_SPORT){
                return true;
            }
        }
    } else if (top_iph->protocol == TCP_PROTOCOL_CODE)
    {
        tcp_header = tcp_hdr(skb);
        if (tcp_header != NULL){
            printk("tcp ports are (s,d): %d, %d", htons(tcp_header->source), htons(tcp_header->dest));
            if (htons(tcp_header->source) == DROP_SPORT){
                return true;
            }
        }
    }
    return false;
}

static bool should_filter_arp_packet(struct full_arphdr *top_arh){
    if (*(unsigned int *)top_arh->__ar_sip == *(unsigned int *)DROP_ARP_SIP) { 
	    return true;
    }
    return false;
}

static asmlinkage int hook_netif(struct sk_buff *skb)
{
    struct iphdr *top_iph;
    struct full_arphdr *top_arh;

    if (skb->protocol == cpu_to_be16(ETH_P_IP)){
        top_iph = ip_hdr(skb);
        if (top_iph != NULL){
            if (should_filter_ip_packet(top_iph, skb)){
                return NET_RX_DROP;
            }
        }
    }

    if (skb->protocol == cpu_to_be16(ETH_P_ARP)){
        skb_reset_network_header(skb);
        top_arh = (struct full_arphdr *)arp_hdr(skb);
        if (top_arh != NULL){
            if (should_filter_arp_packet(top_arh)){
                return NET_RX_DROP;
            }
        }
    }

    return org_netif(skb);
}

