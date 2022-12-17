#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "firewall.h"

#define ANY "ANY"



void show_possible_commands()
{
    printf("\n"
            "Commands:\n"
            "\t--help \t\t\t\t Show available commands\n"
            "\t--all \t\t\t\t Show all the rules\n"
            "\t--block_spoof \t\t\t Start or stop blocking suspicious packages\n"
            "\t--block_u \t\t\t Start or stop blocking unauthorotive DNS answers\n"
            "\t--add RULE \t\t\t Add the rule\n"
            "\t--delete RULE \t\t\t Delete the rule\n\n"
            "Rule parameters:\n"
            "\t  --in or --out \t\t Input or Output packages (required)\n"
            "\t  --protocol PROTOCOL\t\t Protocol = {TCP, UDP}\n"
            "\t  --src_ip IP\t\t\t Source IP\n"
            "\t  --src_port PORT\t\t Source port\n"
            "\t  --dest_ip IP\t\t\t Destination IP\n"
            "\t  --dest_port PORT\t\t Destination port\n"
            "\n"
           );
}


void print_rules_table_header()
{
    printf("direction \t protocol \t source IP \t source port \t destination IP \t destination port\n");

    for (int i = 0; i < 110; i++)
        printf("¯");
    printf("\n");
}


int print_rules_table()
{
    int fd;
    char *buf;
    struct firewall_rule *rule;
    struct in_addr addr;

    fd = open("/proc/" PROC_FILE_NAME, O_RDONLY);
    if (fd < 0)
        return DEVICE_NOT_AVAILABLE;

    buf = (char *)malloc(sizeof(struct firewall_rule));
    if (buf == NULL)
        return MEMORY_ERROR;

    print_rules_table_header();
    
    while (read(fd, buf, sizeof(struct firewall_rule)) > 0)
    {
		rule = (struct firewall_rule *)buf;
		printf("%-16s ", rule->in == IN ? "IN" : "OUT");
        
        if (rule->protocol != NOT_STATED)
        {
            if (rule->protocol == IPPROTO_TCP)
                printf("%-15s ", TCP_PROTOCOL);
            else if (rule->protocol == IPPROTO_UDP)
                printf("%-15s ", UDP_PROTOCOL);
        }
        else
            printf("%-15s ", ANY);
        
        if (rule->src_ip[0] != '\0')
        {
            printf("%-15s ", rule->src_ip);
        }
        else
            printf("%-15s ", ANY);
        
        if (rule->src_port != NOT_STATED)
            printf("%-15d ", ntohs(rule->src_port));
        else
            printf("%-15s ", ANY);

        if (rule->dest_ip[0] != '\0')
        {
            printf("%-24s ", rule->dest_ip);
        }
        else
            printf("%-24s ", ANY);
        
        if (rule->dest_port != NOT_STATED)
            printf("%-16d ", ntohs(rule->dest_port));
        else
            printf("%-16s ", ANY);

        printf("\n");
	}

	free(buf);
	close(fd);

    return EXIT_SUCCESS;
}


int send_rule_to_module(struct firewall_command *comm)
{
    int fd;
    int count_byte;

    fd = open("/proc/" PROC_FILE_NAME, O_WRONLY | O_APPEND);
    if (fd < 0)
        return DEVICE_NOT_AVAILABLE;

    write(fd, comm, sizeof(*comm));

    close(fd);

    return EXIT_SUCCESS;
}


uint64_t parse_arg_as_number(const char *str, int min_value, int max_value)
{
    int num;
    char *end;

    num = strtol(str, &end, 10);
    if (num < min_value || num > max_value || str == end)
        return EXIT_FAILURE;

    return num;
}


int parse_arg_as_protocol(const char *protocol)
{
    if (strcmp(protocol, TCP_PROTOCOL) == 0)
        return IPPROTO_TCP;

    if (strcmp(protocol, UDP_PROTOCOL) == 0)
        return IPPROTO_UDP;
    printf("%s.%s", protocol, TCP_PROTOCOL);
    return EXIT_FAILURE;
}



void initialize_new_command(struct firewall_command *comm)
{
    comm->action = NONE;
    comm->rule.in = NOT_STATED;
    comm->rule.src_ip[0] = '\0';
    comm->rule.dest_ip[0] = '\0';
    comm->rule.protocol = NOT_STATED;
    comm->rule.src_port = NOT_STATED;
    comm->rule.dest_port = NOT_STATED;
}



int parse_command_from_console(int argc, char **argv, struct firewall_command *res_comm)
{
    int res, comm_ind, protocol;
    int64_t param;
    const char* short_comm = "ad:Aiop:s:r:t:e:h:b";
    struct in_addr addr;
    struct firewall_command comm;

    if (argc == 1)
    {
        show_possible_commands();
        return LACK_ARGUMENTS;
    }

    struct option long_comm[] =
    {
        {"add", no_argument, 0, 'a'},
        {"delete", no_argument, 0, 'd'},
        {"all", no_argument, 0, 'A'},
        {"in", no_argument, 0, 'i'},
        {"out", no_argument, 0, 'o'},
        {"protocol", required_argument, 0, 'p'},
        {"src_ip", required_argument, 0, 's'},
        {"src_port", required_argument, 0, 'r'},
        {"dest_ip", required_argument, 0, 't'},
        {"dest_port", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"block_spoof", no_argument, 0, 'b'},
        {"block_u", no_argument, 0, 'u'},
        {NULL, 0, NULL, 0}
    };
    

    initialize_new_command(&comm);
    
    while (1)
    {
        res = getopt_long(argc, argv, short_comm, long_comm, &comm_ind);
        if (res < 0)
            break;
    
        switch (res)
        {
        case 'a':
            if (comm.action != NONE)
                return ACTION_MENTIONED;

            comm.action = ADD;
            break;

        case 'd':
            if (comm.action != NONE)
                return ACTION_MENTIONED;

            comm.action = DELETE;
            break;

        case 'A':
            if (comm.action != NONE)
                return ACTION_MENTIONED;

            comm.action = SHOW;
            break;
        case 'b':
            if (comm.action != NONE)
                return ACTION_MENTIONED;

            comm.action = BLOCK_SPOOF;
            break;
        case 'u':
            if (comm.action != NONE)
                return ACTION_MENTIONED;

            comm.action = BLOCK_U;
            break;

        case 'i':
            if (comm.rule.in == OUT)
                return DIRECTION_MENTIONED;

            comm.rule.in = IN;
            break;

        case 'o':
            if (comm.rule.in == IN)
                return DIRECTION_MENTIONED;

            comm.rule.in = OUT;
            break;

        case 'p':
            if (comm.rule.protocol != NOT_STATED)
                return PROTOCOL_MENTIONED;

            protocol = parse_arg_as_protocol(optarg);
            if (protocol == EXIT_FAILURE)
                return WRONG_PROTOCOL;

            comm.rule.protocol = protocol;
            break;

        case 's':
            if (!inet_aton(optarg, &addr))
                return INCORRECT_SRC_IP;
                
            strncpy(comm.rule.src_ip, optarg, strlen(optarg));
            break;

        case 't':
            if (!inet_aton(optarg, &addr))
                return INCORRECT_DEST_IP;

            strncpy(comm.rule.dest_ip, optarg, strlen(optarg));
            break;
    
        case 'r':
            if (comm.rule.src_port != NOT_STATED)
                return SRC_PORT_MENTIONED;

            param = parse_arg_as_number(optarg, 0, USHRT_MAX);
            if (param == EXIT_FAILURE)
                return INCORRECT_SRC_PORT;

            comm.rule.src_port = htons((uint16_t)param);
            break;


        case 'e':
            if (comm.rule.dest_port != NOT_STATED)
                return DEST_PORT_MENTIONED;

            param = parse_arg_as_number(optarg, 0, USHRT_MAX);
            if (param == EXIT_FAILURE)
                return INCORRECT_DEST_PORT;

            comm.rule.dest_port = htons((uint16_t)param);
            break;
        
        default:
            show_possible_commands();
            return EXIT_FAILURE;
        }
    }

    if (comm.action == NONE)
        return ACTION_NOT_MENTIONED;

    if (comm.action == SHOW || comm.action == BLOCK_SPOOF || comm.action == BLOCK_U)
    {
        *res_comm = comm;
        return EXIT_SUCCESS;
    }

    if (comm.rule.in == NOT_STATED)
        return DIRECTION_NOT_MENTIONED;

    if (comm.rule.src_ip[0] == '\0' && comm.rule.src_port == NOT_STATED && \
        comm.rule.dest_ip[0] == '\0' && comm.rule.dest_port == NOT_STATED && \
        comm.rule.protocol == NOT_STATED)
        return KEYS_NOT_MENTIONED;

    *res_comm = comm;

    return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{
    struct firewall_command comm;
    struct in_addr addr;
    int res;

    res = parse_command_from_console(argc, argv, &comm);

    if (res)
    {
        switch (res)
        {
        case LACK_ARGUMENTS:
            printf("ERROR: not enough arguments.\n");
            break;
        case ACTION_MENTIONED:
            printf("ERROR: action is already mentioned\n");
            break;
        case DIRECTION_MENTIONED:
            printf("ERROR: direction is already mentioned\n");
            break;
        case PROTOCOL_MENTIONED:
            printf("ERROR: protocol is already mentioned\n");
            break;
        case WRONG_PROTOCOL:
            printf("ERROR: wrong parameter of protocol\n");
            break;
        case SRC_IP_MENTIONED:
            printf("ERROR: source IP is already mentioned\n");
            break;
        case INCORRECT_SRC_IP:
            printf("ERROR: incorrect source IP\n");
            break;
        case DEST_IP_MENTIONED:
            printf("ERROR: destination IP is already mentioned\n");
            break;
        case INCORRECT_DEST_IP:
            printf("ERROR: incorrect destination IP\n");
            break;
        case SRC_PORT_MENTIONED:
            printf("ERROR: source port is already mentioned\n");
            break;
        case INCORRECT_SRC_PORT:
            printf("ERROR: incorrect source port\n");
            break;
        case DEST_PORT_MENTIONED:
            printf("ERROR: destination port is already mentioned\n");
            break;
        case INCORRECT_DEST_PORT:
            printf("ERROR: incorrect destination port\n");
            break;
        case ACTION_NOT_MENTIONED:
            printf("ERROR: action (add/delete) is not mentioned\n");
            break;
        case DIRECTION_NOT_MENTIONED:
            printf("ERROR: direction (in/out) is not mentioned\n");
            break;
        case KEYS_NOT_MENTIONED:
            printf("ERROR: keys are not mentioned\n");
            break;
        default:
            break;
        }
        return res;
    }
        

    switch (comm.action)
    {
        case ADD:
        case DELETE:
            res = send_rule_to_module(&comm);

            switch (res)
            {
                case DEVICE_NOT_AVAILABLE:
                    printf("ERROR: denied access to the device\n");
                    break;
                case RULE_ADDITION_FAILED:
                    printf("ERROR: operation was failed.\n");
                    break;
                default:
                    break;
            }
            break;
            
        case SHOW:
            res = print_rules_table();

            switch (res)
            {
                case DEVICE_NOT_AVAILABLE:
                    printf("ERROR: denied access to the device\n");
                    break;
                case MEMORY_ERROR:
                    printf("ERROR: problems with memory allocation");
                    break;
                default:
                    break;
            }
            break;
            
        case BLOCK_SPOOF:
            res = send_rule_to_module(&comm);

            switch (res)
            {
                case DEVICE_NOT_AVAILABLE:
                    printf("ERROR: denied access to the device\n");
                    break;
                case RULE_ADDITION_FAILED:
                    printf("ERROR: operation was failed.\n");
                    break;
                default:
                    break;
            }
        case BLOCK_U:
            res = send_rule_to_module(&comm);

            switch (res)
            {
                case DEVICE_NOT_AVAILABLE:
                    printf("ERROR: denied access to the device\n");
                    break;
                case RULE_ADDITION_FAILED:
                    printf("ERROR: operation was failed.\n");
                    break;
                default:
                    break;
            }
    }

    return EXIT_SUCCESS;
}
