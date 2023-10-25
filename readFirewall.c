#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define IP_LENGTH 18
#define PORT_LENGTH 11

FILE* open_rules(const char* filename);
void get_ports(long *ports, const char *port_range);
bool check_port_range(const long* port_range);
void get_ip(long nums[][4], char* ip, unsigned int *ip_count);
bool check_ip(const long nums[][4], unsigned int ip_count);
void print_ip(const long nums[]);

typedef struct Rule {
    long ip_nums[2][4];
    long ports[2];
    bool ill_formed;
    unsigned int ip_count;
    unsigned int port_count;
} Rule;

Rule make_rule(char *ip_str, char *port_str);
int compare_rules(const void* first, const void* second);
void print_rule(Rule* rule);

int main(int argc, char **argv) {
    FILE* rule_file = open_rules(argv[1]); // argv[1] is the filename passed from the command-line
    char ip_str[IP_LENGTH];
    char port_str[PORT_LENGTH];
    unsigned int line_count = 0;

    // calculate the number of lines
    while (EOF != (fscanf(rule_file, "%*[^\n]"), fscanf(rule_file,"%*c"))) ++line_count;
    rewind(rule_file);
    Rule* rules;
    if ((rules= (Rule*) malloc(line_count*sizeof(Rule))) == NULL) {
        printf("Allocation failed.");
        exit(-1);
    }

    for (int i=0; i < line_count; i++) {
        fscanf(rule_file, "%s %s", ip_str, port_str);
        *(rules+i) = make_rule(ip_str, port_str);
    }
    qsort(rules, line_count, sizeof(Rule), compare_rules);
    for (int i=0; i < line_count; i++) {
        print_rule(rules+i);
    }
    free(rules);
    fclose(rule_file);
    return 0;
}

FILE* open_rules(const char* filename) {
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Cannot open file.\n");
        exit(-1);
    }
    return fp;
}

void get_ip(long nums[][4], char* ip, unsigned int *ip_count) {
    char* ip_copy = calloc(strlen(ip), sizeof(char));
    strcpy(ip_copy, ip);

    *ip_count = strchr(ip_copy, '-') ? 2 : 1;
    long num = 0;
    char delimiters[] = "-.";
    char* token = strtok(ip_copy, delimiters);
    int count=0;

    for (int i = 0; token != NULL; i++) {
        num = strtol(token, NULL, 10);
        if (*ip_count == 2) nums[i / 4][i % 4] = num;
        else nums[1][i] = num;
        count++;
        token = strtok(NULL, delimiters);
    }
    free(ip_copy);
}

bool check_ip(const long nums[][4], const unsigned int ip_count) {
    // CHECK FOR RANGE
    bool less = false;
    long num1, num2;
    if (ip_count == 1) {
        for (int i=0; i < 4; i++) {
            num1 = nums[1][i];
            if (num1 > 255 || num1 < 0) return false;
        }
        return true;
    }
    for (int i=0; i < 4 && !less; i++) {
        num1 = nums[0][i];
        num2 = nums[1][i];
        if (num1 > num2) {
            return false;
        } else less = (num1 < num2);
    }
    return less;
}

void get_ports(long *ports, const char *port_range) {
    long first = strtol(port_range, NULL, 10), second;
    char* hyphen_index = strchr(port_range, '-');
    if (hyphen_index) {
        second = strtol(hyphen_index+1, NULL, 10);
        ports[0] = first;
        ports[1] = second;
    } else {
        ports[0] = 0;
        ports[1] = first;
    }
}

bool check_port_range(const long* port_range) {
    return (port_range[0] < port_range[1]) && ((port_range[0] < 65535) || (port_range[1] < 65535));
}

Rule make_rule(char *ip_str, char *port_str) {
    Rule new_rule;
    get_ip(new_rule.ip_nums, ip_str, &new_rule.ip_count);
    get_ports(new_rule.ports, port_str);
    new_rule.ill_formed = !(check_ip(new_rule.ip_nums, new_rule.ip_count) && check_port_range(new_rule.ports));

    return new_rule;
}

int compare_rules(const void* first, const void* second) {
    Rule* rule1 = (Rule*) first;
    Rule* rule2 = (Rule*) second;
    unsigned int rule1_ip_index = 2 - rule1->ip_count;
    unsigned int rule2_ip_index = 2 - rule2->ip_count;
    for (int i=0; i < 4; i++) {
        if (rule1->ip_nums[rule1_ip_index][i] > rule2->ip_nums[rule2_ip_index][i]) return 1;
        if (rule1 -> ip_nums[rule1_ip_index][i] < rule2->ip_nums[rule2_ip_index][i]) return -1;
    }

    unsigned int rule1_port_index = 2 - rule1->port_count;
    unsigned int rule2_port_index = 2 - rule2->port_count;
    if (rule1->ports[rule1_port_index] > rule2->ports[rule2_port_index]) return 1;
    if (rule1->ports[rule1_port_index] < rule2->ports[rule2_port_index]) return -1;
    return 0;
}

void print_rule(Rule* rule) {
    if (rule->ill_formed) printf("Ill formed rule:\n");
    if (rule->ip_count > 1) {
        print_ip(rule->ip_nums[0]);
        printf("-");
    }
    print_ip(rule->ip_nums[1]);
    if (rule->port_count == 1) printf(" %ld\n", rule->ports[1]);
    else printf(" %ld-%ld\n", rule->ports[0], rule->ports[1]);
}

void print_ip(const long nums[]) {
    char delim;
    for (int i=0; i < 4; i++) {
        if (i < 3) delim = '.';
        else delim = 0;
        printf("%ld%c", nums[i], delim);
    }
}
