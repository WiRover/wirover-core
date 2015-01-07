#include <json/json.h>
#include <arpa/inet.h>

#include "debug.h"
#include "policy_table.h"

static policy_entry *   default_ingress_policy;
static policy_entry *   default_egress_policy;
static int              policy_count;
static policy_entry **  policies;
static int              init = 0;

static policy_entry** load_policies(int * count);

static policy_entry * alloc_policy() {
    policy_entry * output = ( policy_entry *)malloc(sizeof( policy_entry));
    memset(output, 0, sizeof( policy_entry));
    output->action = POLICY_ACT_ENCAP;
    return output;
}

static void update_policies() {
    policies = load_policies(&policy_count);
    print_policies();
}

int init_policy_table() {
    default_ingress_policy = alloc_policy();
    default_egress_policy = alloc_policy();
    default_ingress_policy->action = POLICY_ACT_DECAP;
    default_egress_policy->action = POLICY_ACT_ENCAP;
    update_policies();
    init = 1;
    return SUCCESS;
}

static json_object * get_table() {
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
    json_object * table = json_tokener_parse(buffer);
    return table;
}

static int parse_policy( json_object * jobj_policy,  policy_entry *pe) {
    json_object * value;

    //--ACTION--//
    value = json_object_object_get(jobj_policy, "action");
    if(!value)
        goto failure_print;

    if(json_object_is_type(value, json_type_string)) {
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
    } else if(json_object_is_type(value, json_type_int)) {
        // Allow direct input of integer values for experimental policies.
        pe->action = json_object_get_int(value);
    } else {
        goto failure_print;
    }

    //--PROTOCOL--//
    value = json_object_object_get(jobj_policy, "protocol");
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

    //--DIRECTION--//
    value = json_object_object_get(jobj_policy, "direction");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * dir_str = json_object_get_string(value);
        if (strcmp(dir_str, "ingress") == 0) {
            pe->direction = DIR_INGRESS;
        }
        else if (strcmp(dir_str, "egress") == 0) {
            pe->direction = DIR_EGRESS;
        }
        else if (strcmp(dir_str, "both") == 0) {
            pe->direction = DIR_BOTH;
        }
        else {
            goto failure_print;
        }
    }
    else { pe->direction = DIR_BOTH; }

    //--LOCAL--//
    value = json_object_object_get(jobj_policy, "local");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * src_str = json_object_get_string(value);
        inet_pton(AF_INET, src_str, &pe->ft.local);
        inet_pton(AF_INET, "255.255.255.255", &pe->local_netmask);
    }

    //--LOCAL NETMASK--//
    value = json_object_object_get(jobj_policy, "local_netmask");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * src_net_str = json_object_get_string(value);
        inet_pton(AF_INET, src_net_str, &pe->local_netmask);
        pe->ft.local &= pe->local_netmask;
    }

    //--REMOTE--//
    value = json_object_object_get(jobj_policy, "remote");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * remote_str = json_object_get_string(value);
        inet_pton(AF_INET, remote_str, &pe->ft.remote);
        inet_pton(AF_INET, "255.255.255.255", &pe->remote_netmask);
    }

    //--REMOTE NETMASK--//
    value = json_object_object_get(jobj_policy, "remote_netmask");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * remote_net_str = json_object_get_string(value);
        inet_pton(AF_INET, remote_net_str, &pe->remote_netmask);
        pe->ft.remote &= pe->remote_netmask;
    }

    //--RATE LIMIT--//
    value = json_object_object_get(jobj_policy, "rate_limit");
    if(value != NULL && json_object_is_type(value, json_type_double)) {
        pe->rate_limit = json_object_get_double(value);
    }

    return SUCCESS;
failure_print:
    DEBUG_MSG("Failed to parse policy %s", json_object_to_json_string(jobj_policy));
    return FAILURE;
}

int get_policy_by_tuple(struct flow_tuple *ft, policy_entry *policy, int dir) {
    if(!init) { DEBUG_MSG("Policy table must be initialized"); return NO_MATCH; }
    int count = policy_count;
    for(int i = 0; i < count; i++) {
        *policy = *policies[i];
        if((policy->direction & dir) == 0) { continue; }
        if(policy->ft.local != (ft->local & policy->local_netmask)) { continue; }
        if(policy->ft.remote != (ft->remote & policy->remote_netmask)) { continue; }
        if((policy->ft.proto != 0) && policy->ft.proto != ft->proto) { continue; }
        return SUCCESS;
    }

    *policy = dir == DIR_INGRESS ? *default_ingress_policy : *default_egress_policy;
    return NO_MATCH;
}

static policy_entry** load_policies(int * count) {
    *count = 0;
    json_object * table = get_table();
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
    char l_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->ft.local, l_str, sizeof(l_str));
    char l_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->local_netmask, l_net_str, sizeof(l_net_str));
    char r_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->ft.remote, r_str, sizeof(r_str));
    char r_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->remote_netmask, r_net_str, sizeof(r_net_str));
    char *dir_str;
    if(pe->direction == DIR_INGRESS) { dir_str = "I"; }
    if(pe->direction == DIR_EGRESS) { dir_str = "O"; }
    if(pe->direction == DIR_BOTH) { dir_str = "*"; }
    DEBUG_MSG("direction: %s local: %s local_net: %s remote: %s remote_net: %s proto: %d act: %d rate: %f",
        dir_str, l_str, l_net_str, r_str, r_net_str, pe->ft.proto, pe->action, pe->rate_limit);
}

void print_policies() {
    DEBUG_MSG("Policies(%d):", policy_count);
    for(int i = 0; i < policy_count; i++){
        print_policy_entry(policies[i]);
    }
}
