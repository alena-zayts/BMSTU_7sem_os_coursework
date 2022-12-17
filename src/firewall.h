#ifndef FW_H
#define FW_H

#define LACK_ARGUMENTS              -11
#define DEVICE_NOT_AVAILABLE        -12
#define RULE_ADDITION_FAILED        -13
#define MEMORY_ERROR                -14


#define INCORRECT_SRC_IP            -21
#define INCORRECT_DEST_IP           -22
#define INCORRECT_SRC_PORT          -23
#define INCORRECT_DEST_PORT         -24


#define ACTION_MENTIONED            -41
#define DIRECTION_MENTIONED         -42
#define PROTOCOL_MENTIONED          -43
#define WRONG_PROTOCOL              -44
#define SRC_IP_MENTIONED            -45
#define DEST_IP_MENTIONED           -46
#define SRC_PORT_MENTIONED          -47
#define DEST_PORT_MENTIONED         -48
#define ACTION_NOT_MENTIONED        -49
#define DIRECTION_NOT_MENTIONED     -50
#define KEYS_NOT_MENTIONED          -51



#define IN          1
#define OUT         0
#define NOT_STATED 10

#define TCP_PROTOCOL    "TCP"
#define UDP_PROTOCOL    "UDP"


#define PROC_FILE_NAME "blocklist"
#define COUNT_BLOCK 50 // длина списка правил фильтрации
#define BUFFER_SIZE 512
#define IP_MAX_LEN 30


enum actions_enum
{
    ADD = 1,
    DELETE = 2,
    SHOW = 3,
    BLOCK_SPOOF = 4,
    BLOCK_U = 5,
    NONE = 0
};

struct firewall_rule
{
    u_int32_t in;
    u_int16_t src_port;
    u_int16_t dest_port;
    u_int8_t protocol;
    char src_ip[IP_MAX_LEN];
    char dest_ip[IP_MAX_LEN];
    char filler[2];
};

struct firewall_command
{
    enum actions_enum action;
    struct firewall_rule rule;
};


#endif // FW_H
