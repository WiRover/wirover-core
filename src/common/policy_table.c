#include <json/json.h>
#include <arpa/inet.h>

#include "debug.h"
#include "policy_table.h"

static policy_entry *   default_policy;
static int              ingress_policy_count;
static policy_entry **  ingress_policies;
static int              egress_policy_count;
static policy_entry **  egress_policies;
static int              init = 0;

static policy_entry** load_policies(int dir, int * count);

static policy_entry * alloc_policy() {
    policy_entry * output = ( policy_entry *)malloc(sizeof( policy_entry));
    memset(output, 0, sizeof( policy_entry));
    output->action = POLICY_ACT_ENCAP;
    return output;
}

static void update_policies() {
    ingress_policies = load_policies(INGRESS, &ingress_policy_count);
    egress_policies = load_policies(EGRESS, &egress_policy_count);
    print_policies();
}

int init_policy_table() {
    default_policy = alloc_policy();
    update_policies();
    init = 1;
    return SUCCESS;
}

static json_object * get_table(int dir) {
    char * buffer = 0;
    long length;
    FILE * f = fopen (POLICY_PATH, "rb");
    if(f == 0) { return 0; }
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = malloc (length + 1);
    buffer[length] = 0;
    if (buffer)
    {
        fread (buffer, 1, length, f);
    }
    fclose (f);
    json_object * tables = json_tokener_parse(buffer);
    return json_object_object_get(tables, dir == 0 ? "ingress" : "egress");
}

static int parse_policy( json_object * jobj_policy,  policy_entry *pe) {
    json_object * value;
    //--ACTION--//
    value = json_object_object_get(jobj_policy, "action");
    if(value == NULL || !json_object_is_type(value, json_type_string)) { goto failure_print; }
    const char * action = json_object_get_string(value);
    if (strcmp(action, "encap") == 0) {
        pe->action = POLICY_ACT_ENCAP;
    }
    else if (strcmp(action, "decap") == 0) {
        pe->action = POLICY_ACT_DECAP;
    }
    else if (strcmp(action, "nat") == 0) {
        pe->action = POLICY_ACT_NAT;
    }
    else if (strcmp(action, "pass") == 0) {
        pe->action = POLICY_ACT_PASS;
    }
    else if (strcmp(action, "drop") == 0) {
        pe->action = POLICY_ACT_DROP;
    }
    else {
        goto failure_print;
    }
    //--PROTOCOL--//
    value = json_object_object_get(jobj_policy, "proto");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * proto_str = json_object_get_string(value);
        if (strcmp(proto_str, "tcp") == 0) {
            pe->ft.proto = 6;
        }
        else if (strcmp(proto_str, "udp") == 0) {
            pe->ft.proto = 17;
        }
        else if (strcmp(proto_str, "any") == 0) {
            pe->ft.proto = 0;
        }
        else {
            goto failure_print;
        }
    }


    //--SOURCE--//
    value = json_object_object_get(jobj_policy, "src");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * src_str = json_object_get_string(value);
        inet_pton(AF_INET, src_str, &pe->ft.src);
        inet_pton(AF_INET, "255.255.255.255", &pe->src_netmask);
    }

    //--SOURCE NETMASK--//
    value = json_object_object_get(jobj_policy, "src_net");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * src_net_str = json_object_get_string(value);
        inet_pton(AF_INET, src_net_str, &pe->src_netmask);
        pe->ft.src &= pe->src_netmask;
    }

    //--DESTINATION--//
    value = json_object_object_get(jobj_policy, "dst");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * dst_str = json_object_get_string(value);
        inet_pton(AF_INET, dst_str, &pe->ft.dst);
        inet_pton(AF_INET, "255.255.255.255", &pe->dst_netmask);
    }

    //--DESTINATION NETMASK--//
    value = json_object_object_get(jobj_policy, "dst_net");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * dst_net_str = json_object_get_string(value);
        inet_pton(AF_INET, dst_net_str, &pe->dst_netmask);
        pe->ft.dst &= pe->dst_netmask;
    }


    return SUCCESS;
failure_print:
    DEBUG_MSG("Failed to parse policy %s", json_object_to_json_string(jobj_policy));
    return FAILURE;
}

int get_policy_by_tuple(struct flow_tuple *ft, policy_entry *policy, int dir) {
    policy_entry ** policies = dir == INGRESS ? ingress_policies : egress_policies;
    int count = dir == INGRESS ? ingress_policy_count : egress_policy_count;
    for(int i = 0; i < count; i++) {
        *policy = *policies[i];
        if(policy->ft.src != (ft->src & policy->src_netmask)) { continue; }
        if(policy->ft.dst != (ft->dst & policy->dst_netmask)) { continue; }
        if((policy->ft.proto != 0) && policy->ft.proto != ft->proto) { continue; }
        return SUCCESS;
    }

    *policy = *default_policy;
    return NO_MATCH;
}

int get_policy_by_index(int index,  policy_entry *policy, int dir) {

    
    *policy = *default_policy;
    return NO_MATCH;
}

static policy_entry** load_policies(int dir, int * count) {
    *count = 0;
    json_object * table = get_table(dir);
    if(table == 0) { return 0; }
    if(!json_object_is_type(table, json_type_array)) {
        DEBUG_MSG("Policy table is formatted incorrectly");
        goto default_return;
    }
    *count = json_object_array_length(table);
    policy_entry ** output = ( policy_entry **)malloc(sizeof(policy_entry *) * *count);
    int result = 0;
    for(int i = 0; i < *count; i++) {
        output[i] = alloc_policy();
        result = parse_policy(json_object_array_get_idx(table, i), output[i]);
        if(result != SUCCESS) {
            DEBUG_MSG("Failed to parse a policy in the table");
            goto free_return;
        }
    }
    return output;

free_return:
    free(output);
default_return:
    *count = 1;
    output = ( policy_entry **)malloc(sizeof( policy_entry));
    output[0] = alloc_policy();
    return output;
}

//---------DEBUG METHODS------------//

void print_policy_entry(policy_entry * pe) {
    char src_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->ft.src, src_str, sizeof(src_str));
    char src_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->src_netmask, src_net_str, sizeof(src_net_str));
    char dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->ft.dst, dst_str, sizeof(dst_str));
    char dst_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->dst_netmask, dst_net_str, sizeof(dst_net_str));
    DEBUG_MSG("src: %s src_net: %s dst: %s dst_net: %s proto: %d act: %d", src_str, src_net_str, dst_str, dst_net_str, pe->ft.proto, pe->action);
}

void print_policies() {
    DEBUG_MSG("Ingress policies(%d):", ingress_policy_count);
    for(int i = 0; i < ingress_policy_count; i++){
        print_policy_entry(ingress_policies[i]);
    }
    DEBUG_MSG("Egress policies(%d):", egress_policy_count);
    for(int i = 0; i < egress_policy_count; i++){
        print_policy_entry(egress_policies[i]);
    }
}
