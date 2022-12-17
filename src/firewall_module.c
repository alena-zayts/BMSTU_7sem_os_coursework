#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fcntl.h>


#include "firewall.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zaytseva Alena");
MODULE_DESCRIPTION("Firewall Kernel Module");

struct firewall_rule iniplist[COUNT_BLOCK]; // список правил для входящих пакетов
struct firewall_rule outiplist[COUNT_BLOCK]; // список правил для исходящих пакетов

int in_index = 0, out_index= 0; //  индексы для iniplist и outiplist

static struct proc_dir_entry *proc_file;

static struct nf_hook_ops nfho_in, nfho_out; // входящий и исходящий трафик
struct sk_buff *sock_buff;

char *localhost = "127.0.0.1";
int bs = 0; // blocking spoofs or not   
int bu = 0; // blocking unauthorotive dns or not


#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DMSG(msg_fmt, msg_args...) \
    printk(KERN_INFO "FW: %s(%04u): " msg_fmt "\n", FILE_NAME, __LINE__, ##msg_args)


// DNS CLASSes
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
enum CLASS_LIST
{
    CLASS_IN = 1,
    CLASS_RESERVED = 65535
};

// Resource Record (RR) TYPEs
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
enum RR_TYPE_LIST
{
    RR_TYPE_A = 1,
    RR_TYPE_CNAME = 5,
    RR_TYPE_AAAA = 28,
    RR_TYPE_RESERVED = 65535
};


// DNS пакет.
struct dnshdr
{
    __be16 id;
#if defined (__LITTLE_ENDIAN_BITFIELD)
    __u8 rd:1,
         tc:1,
         aa:1,
         opcode:4,
         qr:1;
    __u8 rcode:4,
         z:3,
         ra:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8 qr:1,
         opcode:4,
         aa:1,
         tc:1,
         rd:1;
    __u8 ra:1,
         z:3,
         rcode:4;
#else
#error "unknown endian type"
#endif
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

struct dns_question_section
{
    char *qname;
    __u16 qtype;
    __u16 qclass;
};

struct dns_answer_section
{
    char *name;
    __u16 type;
    __u16 class;
    __u32 ttl;
    __u16 rdlength;
    void *rdata;
};

// парсинг полного доменного имени
static size_t parse_name(
    struct dnshdr *dns_hdr,
    char *name_field,
    char *name_buf,
    size_t buf_size,
    size_t *name_len_buf,
    unsigned int in_recursive)
{
    __u8 *link_name;
    size_t name_offset;
    // длина поля доменного имени.
    size_t flen = 0;
    // длина доменного имени.
    size_t nlen = 0, plen = 0;
    // данные о длине в начале метки.
    size_t llen = 0;


    if(in_recursive == 0)
        buf_size--;

    for(; *name_field != '\0'; name_field++)
    {
        // Проверить, используется ли сжатие.
        if((*name_field & 0xC0) == 0xC0)
        {
            name_offset = ntohs(*((__be16 *) name_field)) & 0x3FFF;
            link_name = ((__u8 *) dns_hdr) + name_offset;

            // Извлечь ссылочное доменное имя.
            parse_name(dns_hdr, link_name, name_buf + nlen, buf_size - nlen, &plen, 1);
            nlen += plen;

            flen += 2;
            // После указателя не должно быть строки доменного имени.
            break;
        }

        if(flen > 0) 
		{
            if(nlen < buf_size)
            {
                name_buf[nlen] = llen == 0 ? '.' : *name_field;
                nlen++;
            }
		}
        llen = llen == 0 ? *name_field : llen - 1;

        flen++;
    }

    name_buf[nlen] = '\0';

    *name_len_buf = nlen;

    return flen;
}

static size_t parse_question_section(struct dnshdr *dns_hdr, __u8 *section_start)
{
    size_t slen = 0;
    void *data_offset;
    char name_buf[256];
    size_t name_len;
    struct dns_question_section dns_qd;


    name_buf[0] = '\0';

    memset(&dns_qd, 0, sizeof(dns_qd));

    data_offset = section_start;
    slen += parse_name(dns_hdr, (char *) data_offset, name_buf, sizeof(name_buf), &name_len, 0);
    DMSG("qname = %s", name_buf);

    data_offset = section_start + slen;
    dns_qd.qtype = ntohs(*((__be16 *) data_offset));
    
    slen += sizeof(dns_qd.qtype);

    data_offset = section_start + slen;
    dns_qd.qclass = ntohs(*((__be16 *) data_offset));

    DMSG("qtype = 0x%04X, qclass = 0x%04X", dns_qd.qtype, dns_qd.qclass);
    DMSG("");
    slen += sizeof(dns_qd.qclass);

    return slen;
}

static size_t parse_answer_section(
    struct dnshdr *dns_hdr,
    __u8 *section_start)
{
    size_t slen = 0;
    void *data_offset;
    char name_buf[256];
    size_t name_len;
    struct dns_answer_section dns_an;


    name_buf[0] = '\0';

    memset(&dns_an, 0, sizeof(dns_an));

    data_offset = section_start;
    slen += parse_name(dns_hdr, (char *) data_offset, name_buf, sizeof(name_buf), &name_len, 0);
    DMSG("name = %s", name_buf);

    data_offset = section_start + slen;
    dns_an.type = ntohs(*((__be16 *) data_offset));
    
    slen += sizeof(dns_an.type);

    data_offset = section_start + slen;
    dns_an.class = ntohs(*((__be16 *) data_offset));
    DMSG("type = 0x%04X, class = 0x%04X", dns_an.type, dns_an.class);
    slen += sizeof(dns_an.class);

    data_offset = section_start + slen;
    dns_an.ttl = ntohl(*((__be32 *) data_offset));
    
    slen += sizeof(dns_an.ttl);

    data_offset = section_start + slen;
    dns_an.rdlength = ntohs(*((__be16 *) data_offset));
    DMSG("ttl = %u, rdlength = %u", dns_an.ttl, dns_an.rdlength);
    slen += sizeof(dns_an.rdlength);

    dns_an.rdata = section_start + slen;
    slen += dns_an.rdlength;

    // информация об ответе
    if(dns_an.class == CLASS_IN)
    {
        if(dns_an.type == RR_TYPE_A)
        {
            DMSG("rdata (IPv4) = %pi4", dns_an.rdata);
        }
        else
        if(dns_an.type == RR_TYPE_AAAA)
        {
            DMSG("rdata (IPv6) = %pi6", dns_an.rdata);
        }
        else
        if(dns_an.type == RR_TYPE_CNAME)
        {
            parse_name(dns_hdr, (char *) dns_an.rdata, name_buf, sizeof(name_buf), &name_len, 0);
            DMSG("rdata (CNAME) = %s", name_buf);
        }
    }
    DMSG("");

    return slen;
}

// парсинг DNS пакета.
static int show_info_about_dns(struct dnshdr *dns_hdr)
{
	DMSG("");
    DMSG("DNS %s", dns_hdr->qr == 0 ? "query" : "response"); 
    DMSG("AA bit: %s", dns_hdr->aa == 1 ? "set" : "unset");
    int is_anauthorotive = dns_hdr->aa == 1 ? 0 : 1;
	
	
	// количество записей в секциях запроса и ответа  
	size_t q_count = ntohs(dns_hdr->qdcount);
	size_t a_count = ntohs(dns_hdr->ancount);
	
	DMSG("question count = %zd, answer count = %zd", q_count, a_count);
	
	__u8 *section_start = ((__u8 *) dns_hdr) + sizeof(struct dnshdr);
	
    size_t s_index, s_count = 0;
    

    // секция запросов
    for(s_index = 0; s_index < q_count; s_index++)
    {
        DMSG("question section %zd", s_index + 1);
        s_count = parse_question_section(dns_hdr, section_start);
        section_start += s_count;
    }

    //  секция ответов
    for(s_index = 0; s_index < a_count; s_index++)
    {
        DMSG("answer section %zd", s_index + 1);
        s_count = parse_answer_section(dns_hdr, section_start);
        section_start += s_count;
    }

    return is_anauthorotive;
}

// проверка DNS.
static int parse_dns(struct sk_buff *skb, unsigned int packet_direction)
{
    struct iphdr *ip4_hdr = ip_hdr(skb);
	
	//iphdr->ihl: длина заголовка -- количество 4-хбайтных слов в заголовке
    struct udphdr *udp_hdr = (struct udphdr *) (((__u8 *) ip4_hdr) + (ip4_hdr->ihl * 4)); 

	// протокол DNS использует порт 53
    __be16 port_number = packet_direction == NF_INET_LOCAL_OUT ? udp_hdr->dest : udp_hdr->source;
    if(port_number != __constant_htons(53))
        return 0;

	struct dnshdr *dns_hdr = (struct dnshdr *) (((__u8 *) udp_hdr) + sizeof(struct udphdr)); //

    // Анализируются только: стандартные запросы (opcode = 0), в которых нет ошибок (код ответа rcode = 0) и 
	// которые содержат записи в секции запроса (question count qdcount > 0)
    if ((dns_hdr->opcode != 0) || (dns_hdr->rcode != 0) || (dns_hdr->qdcount == 0))
        return 0;

    return show_info_about_dns(dns_hdr);
}









/*
 
 Добавление и удаление правил
 
 */
char* str_rule(struct firewall_rule *rule)
{
    int count_bytes = 0;

    char *res = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!res)
    {
        DMSG("error in formating rule");
        return NULL;
    }

    if (rule->in == IN)
        count_bytes += snprintf(res, 10, "IN \t ");
    else
        count_bytes += snprintf(res, 10, "OUT \t ");

    if (rule->src_ip != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 30, "src_ip: %s \t ", rule->src_ip);

    if (rule->src_port != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 20, "src_port: %u \t ", ntohs(rule->src_port));

    if (rule->dest_ip != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 30, "dest_ip: %s \t ", rule->dest_ip);

    if (rule->dest_port != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 20, "dest_port: %u \t ", ntohs(rule->dest_port));

    if (rule->protocol != NOT_STATED)
    {
        if (rule->protocol == IPPROTO_TCP)
            count_bytes += snprintf(res + count_bytes, 20, "protocol: TCP");
        else if (rule->protocol == IPPROTO_UDP)
            count_bytes += snprintf(res + count_bytes, 20, "protocol: UDP");
    }

    return res;
}

char* str_packet(char* src_ip, uint16_t src_port,char* dest_ip, uint16_t dest_port, char *protocol_str)
{
    int count_bytes = 0;

    char *res = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!res)
    {
        printk(KERN_INFO "FIREWALL: error in formating rule");
        return NULL;
    }

    if (src_ip != NOT_STATED)
        count_bytes = snprintf(res + count_bytes, 30, "src_ip: %s\t ", src_ip);

    if (src_port != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 20, "src_port: %u \t ", ntohs(src_port));
    else
        count_bytes += snprintf(res + count_bytes, 20, "src_port: - \t ");

    if (dest_ip != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 30, "dest_ip: %s\t ", dest_ip);

    if (dest_port != NOT_STATED)
        count_bytes += snprintf(res + count_bytes, 20, "dest_port: %u \t ", ntohs(dest_port));
    else
        count_bytes += snprintf(res + count_bytes, 20, "dest_port: - \t ");

    snprintf(res + count_bytes, 20, "protocol: %s", protocol_str);

    return res;
}

void deleteSlashN(char *str) {
	int i = 0;
	while (i < strlen(str))
	{
		if (str[i] == '\n') {
			str[i] = '\0';
			break;
		}
		i++;
	}	
}

static int proc_show(struct seq_file *m, void *v)
{
    DMSG("call proc_show");
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
   DMSG("call proc_open");
   return single_open(file, proc_show, NULL);
}

int cmp_rules(struct firewall_rule *r1, struct firewall_rule *r2)
{
    if (strcmp(r1->src_ip, r2->src_ip))
        return -1;
    if (strcmp(r1->dest_ip, r2->dest_ip))
        return -1;
    if (r1->src_port != r2->src_port)
        return -1;
    if (r1->dest_port != r2->dest_port)
        return -1;
    if (r1->protocol != r2->protocol)
        return -1;
    return 0;
}


int rules_match(struct firewall_rule *r1, struct firewall_rule *r2)
{
    if (strcmp(r1->src_ip, r2->src_ip) && (r1->src_ip[0] != '\0') && (r2->src_ip[0] != '\0'))
        return -1;
    if (strcmp(r1->dest_ip, r2->dest_ip) && (r1->dest_ip[0] != '\0') && (r2->dest_ip[0] != '\0'))
        return -1;
    if ((r1->src_port != r2->src_port) && (r1->src_port != NOT_STATED) && (r2->src_port != NOT_STATED))
        return -1;
    if ((r1->dest_port != r2->dest_port) && (r1->dest_port != NOT_STATED) && (r2->dest_port != NOT_STATED))
        return -1;
    if ((r1->protocol != r2->protocol) && (r1->protocol != NOT_STATED) && (r2->protocol != NOT_STATED))
        return -1;
    return 0;
}

static int check_rule_exists(struct firewall_rule *lst, int last_index, struct firewall_rule *r)
{
    int i = 0;
    while (i < last_index)
    {
        if (!cmp_rules(&(lst[i]), r))
        {
            DMSG("Rule exists");
            return 1;
        }
        i += 1;
    }
    return 0;
}

static void block_spoof(void)
{
    if (bs == 0)
    {
        bs = 1;
        DMSG("Start blocking suspicious packages");
    }
    else
    {
        bs = 0;
        DMSG("Stop blocking suspicious packages");
    }
}

static void block_unauthorotive(void)
{
    if (bu == 0)
    {
        bu = 1;
        DMSG("Start blocking unauthorotive DNS answers");
    }
    else
    {
        bu = 0;
        DMSG("Stop blocking unauthorotive DNS answers");
    }
}

static void add_rule(struct firewall_rule *rule)
{
    deleteSlashN(rule->src_ip);
    deleteSlashN(rule->dest_ip);
    if (rule->in)
    {
        if (check_rule_exists(iniplist, in_index, rule))
            return;
        memcpy(&(iniplist[in_index]), rule, sizeof(struct firewall_rule));
        DMSG("Added new rule to incoming target list: %s", str_rule(rule));
        
        in_index += 1;
    }
    else
    {
        if (check_rule_exists(outiplist, out_index, rule))
            return;
        memcpy(&(outiplist[out_index]), rule, sizeof(struct firewall_rule));
        DMSG("Added new rule to outcoming target list: %s", str_rule(rule));
        out_index += 1;
    }
}

static void del_rule(struct firewall_rule *rule)
{
    struct firewall_rule *lst;
    int *last_index;
    
    if (rule->in == IN)
    {
        lst = iniplist;
        last_index = &in_index;
    }
    else
    {
        lst = outiplist;
        last_index = &out_index;
    }
    
    deleteSlashN(rule->src_ip);
    deleteSlashN(rule->dest_ip);
    
    int i = 0;
    while (i < *last_index)
    {
        if (!cmp_rules(&(lst[i]), rule))
        {
            int j = i;
            while (j + 1 < *last_index)
            {
                memcpy(&(lst[j]), &(lst[j + 1]), sizeof(struct firewall_rule));
                j += 1;
            }
            break;
        }
        i += 1;
    }
    if (i == *last_index)
    {
        DMSG("Rule was not found");
    }
    else
    {
        *last_index = (*last_index) - 1;
        DMSG("Successfully deleted rule");
    }
}


ssize_t write_proc(struct file *filp, const char __user *buff, size_t count, loff_t *f_pos)
{
    struct firewall_command rule_full;

    if (count < sizeof(struct firewall_command))
    {
        DMSG("incorrect rule");
        return -EFAULT;
    }

    if (copy_from_user(&rule_full, buff, count))
    {
        DMSG("copy_from_user error");
        return -EFAULT;
    }
    switch (rule_full.action)
    {
        case BLOCK_SPOOF:
            block_spoof();
            break;
        case BLOCK_U:
            block_unauthorotive();
            break;
        case ADD:
            add_rule(&rule_full.rule);
            break;
        case DELETE:
            del_rule(&rule_full.rule);
            break;
        default:
            DMSG("unknown command");
            break;
    }

    return 0;
}


ssize_t read_proc(struct file *filp, char __user *buff, size_t count, loff_t *f_pos)
{
    static int in_read_index = 0;
    static int out_read_index = 0;
    struct firewall_rule full_rule;
    
    if (in_read_index < in_index)
    {
        memcpy(&full_rule, &(iniplist[in_read_index]), sizeof(struct firewall_rule));
        full_rule.in = IN;
        in_read_index += 1;
    }
    else if (out_read_index < out_index)
    {
        memcpy(&full_rule, &(outiplist[out_read_index]), sizeof(struct firewall_rule));
        
        full_rule.in = OUT;
        out_read_index += 1;
    }
    else
    {
        in_read_index = 0;
        out_read_index = 0;
        return 0;
    }
    
    if (copy_to_user(buff, (char *) &full_rule, count))
    {
        DMSG("copy_to_user error");
        return -EFAULT;
    }
    
    return count;
}

static const struct proc_ops proc_fops = {
      .proc_open = proc_open,
       .proc_release = single_release,
       .proc_read = read_proc,
      .proc_write = write_proc,
};











/*

		Реализация регистрации функций перехвата входящих и исходящих сетевых пакетов.

*/
 
unsigned int hook_func_in(void *info, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int is_unauthorotuve = parse_dns(skb, state->hook);
    if (bu && is_unauthorotuve)
    {
        DMSG("!!! Drop unauthorotive DNS answer");
        return NF_DROP;
    }
	struct iphdr *ip_header;

    sock_buff = skb;
    if(!sock_buff) 
	{ 
		return NF_ACCEPT;
	}
 
 
    ip_header = ip_hdr(sock_buff);   //захват сетевого заголовка

    struct firewall_rule cur_rule;
    cur_rule.in = IN;
    snprintf(cur_rule.src_ip, BUFFER_SIZE, "%pI4", &ip_header->saddr);
    snprintf(cur_rule.dest_ip, BUFFER_SIZE, "%pI4", &ip_header->daddr);
    cur_rule.protocol = ip_header->protocol;
    
    if (ip_header->protocol==IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)skb_transport_header(skb);
        cur_rule.src_port = (unsigned int)ntohs(udp_header->source);
        cur_rule.dest_port = (unsigned int)ntohs(udp_header->dest);
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
        cur_rule.src_port = (unsigned int)ntohs(tcp_header->source);
        cur_rule.dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    else
    {
        cur_rule.src_port = (unsigned int) 0;
        cur_rule.dest_port = (unsigned int) 0;

        //DMSG("......unused proto in, dest_ip: %s", cur_rule.dest_ip);
        //return NF_ACCEPT;
    }
    
    //DMSG("..............in: %s", str_rule(&cur_rule));
    //TODELETE
    if ((bs == 1) && (strcmp(cur_rule.src_ip, localhost)))
    {
        DMSG("Dont drop incoming packet as suspicious for spoof, src_ip: %s", cur_rule.src_ip);
    }
    
    if ((bs == 1) && (!strcmp(cur_rule.src_ip, localhost)))
    {
        DMSG("!!!!!! Drop incoming packet as suspicious for spoof, src_ip: %s", cur_rule.src_ip);
        return NF_DROP;
    }

	int i;
	for (i = 0; i < in_index; i++)
    {
		if (rules_match(&cur_rule, &(iniplist[i])) == 0)
        {
			DMSG("Drop incoming packet: %s", str_rule(&cur_rule));
			return NF_DROP;
		}
	}

    return NF_ACCEPT;
}


unsigned int hook_func_out(void *info, struct sk_buff *skb, const struct nf_hook_state *state)
{
	parse_dns(skb, state->hook);

	struct iphdr *ip_header;

	sock_buff = skb;
	if (!sock_buff) 
	{ 
		return NF_ACCEPT;
	}


	ip_header = ip_hdr(sock_buff);    //захват сетевого заголовка

    struct firewall_rule cur_rule;
    cur_rule.in = OUT;
    snprintf(cur_rule.src_ip, BUFFER_SIZE, "%pI4", &ip_header->saddr);
    snprintf(cur_rule.dest_ip, BUFFER_SIZE, "%pI4", &ip_header->daddr);
    cur_rule.protocol = ip_header->protocol;
    if (ip_header->protocol==IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)skb_transport_header(skb);
        cur_rule.src_port = (unsigned int)ntohs(udp_header->source);
        cur_rule.dest_port = (unsigned int)ntohs(udp_header->dest);
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
        cur_rule.src_port = (unsigned int)ntohs(tcp_header->source);
        cur_rule.dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    else
    {
        cur_rule.src_port = (unsigned int) 0;
        cur_rule.dest_port = (unsigned int) 0;
        //DMSG("......unused proto out, dest_ip: %s", cur_rule.dest_ip);
        //return NF_ACCEPT;
    }
    //DMSG("..............out: %s", str_rule(&cur_rule));
    //TODELETE

    if ((bs == 1) && (!strcmp(cur_rule.src_ip, localhost)))
    {
        DMSG("Dont drop outcoming packet as suspicious for spoof, src_ip: %s", cur_rule.src_ip);
    }
    
    if ((bs == 1) && (strcmp(cur_rule.src_ip, localhost)))
    {
        DMSG("!!!!!! Drop outcoming packet as suspicious for spoof, src_ip: %s", cur_rule.src_ip);
        return NF_DROP;
    }

	int i; 
	for (i = 0; i < out_index; i++)
    {
        if (rules_match(&cur_rule, &(outiplist[i])) == 0)
        {
            DMSG("Drop outcoming packet: %s", str_rule(&cur_rule));
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}






int netfilter_init(void)
{
	
	DMSG("call init");

	/* proc-файл для записи правил */
	proc_file = proc_create(PROC_FILE_NAME, S_IRUGO | S_IWUGO, NULL, &proc_fops);
  	if (!proc_file) 
	{
        DMSG("call proc_create_data() fail");
        return -ENOMEM;
    }
	DMSG("proc file created");	

	/* структура для фильтрации входящих пакетов */
    nfho_in.hook = hook_func_in; // функция, которая будет обрабатывать пакеты
    nfho_in.hooknum = NF_INET_LOCAL_IN; // точка, в которой должна срабатывать функция
    nfho_in.pf = PF_INET; //семейство протоколов
    nfho_in.priority = NF_IP_PRI_FIRST; // приоритет функции (самый высокий)

    /* регистрация структуры */
    if (nf_register_net_hook(&init_net, &nfho_in) < 0)
    {
        DMSG("call nf_register_net_hook(NF_INET_LOCAL_IN) fail");
        return -ENOMEM;
    }

    /*  структура для фильтрации исходящих пакетов*/
	nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
	
	/* регистрация структуры */
    if (nf_register_net_hook(&init_net, &nfho_out) < 0)
    {
        DMSG("call nf_register_net_hook(NF_INET_LOCAL_OUT) fail");
        return -ENOMEM;
    }
	
	DMSG("Firewall module loaded successfully");
    
    return 0;
}
 
void netfilter_exit(void)
{
    DMSG("call exit");
    
	if (proc_file) 
	{
		remove_proc_entry(PROC_FILE_NAME, NULL);
		DMSG("proc file removed");
	}

    nf_unregister_net_hook(&init_net, &nfho_in);     
	nf_unregister_net_hook(&init_net, &nfho_out);
   
	DMSG("Firewall module unloaded successfully");
}

module_init(netfilter_init);
module_exit(netfilter_exit);
