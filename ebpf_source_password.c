#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERVER_PORT 27015
#define SERVER_APPID 730

// header of all steam/source engine server queries
struct __attribute__((packed)) steam_query_header
{
    unsigned int magic; // always 0xFFFFFFFF, can be 0xFFFFFFFE on split packets but i have never seen one
    unsigned char type;
};

// static info between game name and version number in the S2A_INFO_SRC packet
struct __attribute__((packed)) query_static_info
{
    unsigned short app_id;
    unsigned char players;
    unsigned char max_players;
    unsigned char bots;
    unsigned char type;
    unsigned char os;
    unsigned char password;
    unsigned char vac;
};

SEC("tc") int modify_udp_packet(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // check ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    // check IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    if (iph->protocol != 17) // UDP
        return TC_ACT_OK;
    // check UDP header
    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    // check if it's the port of our source server
    if (udph->source == __bpf_htons(SERVER_PORT))
    {
        // check if it's S2A_INFO_SRC packet
        unsigned char *payload = (void *)(udph + 1);
        struct steam_query_header *queryhdr = (void *)(payload);
        if ((void *)(queryhdr + 1) > data_end)
            return TC_ACT_OK;
        if ((void *)(payload + __bpf_ntohs(udph->len) - sizeof(struct udphdr)) > data_end)
            return TC_ACT_OK;
        if (queryhdr->magic != 0xFFFFFFFF) // magic
            return TC_ACT_OK;
        if (queryhdr->type != 'I') // S2A_INFO_SRC
            return TC_ACT_OK;
        //bpf_trace_printk("S2A_INFO_SRC from %d->%d, type '%c'", 36, __bpf_ntohs(udph->source), __bpf_ntohs(udph->dest), queryhdr->type);
        
        // parse through the packet
        char name_buf[256] = {0}; // kinda bad idea to have such a big stack buffer in eBPF i think
        char *name_ptr = (char *)payload + sizeof(struct steam_query_header) + 1;
        long name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name_ptr);
        if (name_len < 0)
            return TC_ACT_OK;
        //bpf_trace_printk("Server name: %s", 16, name_buf);

        name_ptr += name_len;
        name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name_ptr);
        if (name_len < 0)
            return TC_ACT_OK;
        //bpf_trace_printk("Map name: %s", 13, name_buf);

        name_ptr += name_len;
        name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name_ptr);
        if (name_len < 0)
            return TC_ACT_OK;
        //bpf_trace_printk("Folder name: %s", 16, name_buf);

        name_ptr += name_len;
        name_len = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name_ptr);
        if (name_len < 0)
            return TC_ACT_OK;
        //bpf_trace_printk("Game name: %s", 14, name_buf);

        // get the static server info block
        struct query_static_info *server_info = (struct query_static_info *)(name_ptr + name_len);
        if ((void *)(server_info + 1) > data_end)
            return TC_ACT_OK;
        // make sure it's for our appid
        if (server_info->app_id != SERVER_APPID)
            return TC_ACT_OK;
        
        // mark the server as password protected
        //bpf_trace_printk("Password protected %d->%d", 26, server_info->password, 1);
        server_info->password = 1;

        // NOTE: if you plan on extending this code you should familiarise yourself with different games queries
        // eg arma3, the ship, etc

        // TODO calculate UDP checksum. not required, 0 values are ignored, but polite to be correct
        udph->check = 0;
    }

    return TC_ACT_OK;
}

// have to GPL license, "bpf_probe_read_kernel_str" is DRMed
SEC("license") char _license[] = "GPL";
