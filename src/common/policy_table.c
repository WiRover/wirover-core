#include <json/json.h>
#include <arpa/inet.h>

#include "debug.h"
#include "tunnel.h"
#include "policy_table.h"

static policy_entry *   default_policy;
static int              policy_count;
static policy_entry **  policies;
static int              init = 0;

static policy_entry** load_policies(int * count);

static policy_entry * alloc_policy() {
    policy_entry * output = ( policy_entry *)malloc(sizeof( policy_entry));
    memset(output, 0, sizeof( policy_entry));
    output->action = POLICY_ACT_ENCAP;
    output->allow_nat_failover = 1;
    output->link_select = POLICY_LS_WEIGHTED;
    output->direction = DIR_BOTH;
    return output;
}

static void update_policies() {
    policies = load_policies(&policy_count);
    print_policies();
}

int init_policy_table() {
    default_policy = alloc_policy();
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

    //--ALLOW NAT FAILOVER--//
    value = json_object_object_get(jobj_policy, "allow_nat_failover");
    if(json_object_is_type(value, json_type_boolean)) {
        int allow_nat_failover = json_object_get_boolean(value);
        pe->allow_nat_failover = allow_nat_failover;
    }

    //--LINK_SELECT--//
    value = json_object_object_get(jobj_policy, "link_select");
    if(json_object_is_type(value, json_type_string)) {
        const char * action = json_object_get_string(value);
        if (strcmp(action, "weighted") == 0) {
            pe->link_select = POLICY_LS_WEIGHTED;
        }
        else if (strcmp(action, "duplicate") == 0) {
            pe->link_select = POLICY_LS_DUPLICATE;
        }
        else if (strcmp(action, "multipath") == 0) {
            pe->link_select = POLICY_LS_MULTIPATH;
        }
        else if (strcmp(action, "forced") == 0) {
            pe->link_select = POLICY_LS_FORCED;
        }
        else {
            goto failure_print;
        }
    }

    //--preferred_LINK--//
    value = json_object_object_get(jobj_policy, "preferred_link");
    if(json_object_is_type(value, json_type_string)) {
        const char * preferred_link = json_object_get_string(value);
        strncpy(pe->preferred_link, (char * restrict)preferred_link, sizeof(pe->preferred_link));
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
        //Save invalid IP strings to the policy to support advanced policies
        //otherwise match against the exact IP unless a netmask is specified
        if(inet_pton(AF_INET, src_str, &pe->ft.local))
            inet_pton(AF_INET, "255.255.255.255", &pe->local_netmask);
        else
            strncpy(pe->local, src_str, sizeof(pe->local));

    }

    //--LOCAL NETMASK--//
    value = json_object_object_get(jobj_policy, "local_netmask");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * src_net_str = json_object_get_string(value);
        inet_pton(AF_INET, src_net_str, &pe->local_netmask);
        pe->ft.local &= pe->local_netmask;
    }

    //--LOCAL PORT--//
    value = json_object_object_get(jobj_policy, "local_port");
    if(value != NULL && json_object_is_type(value, json_type_int)) {
        pe->ft.local_port = json_object_get_int(value);
    }

    //--REMOTE--//
    value = json_object_object_get(jobj_policy, "remote");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * remote_str = json_object_get_string(value);
        //Save invalid IP strings to the policy to support advanced policies
        //otherwise match against the exact IP unless a netmask is specified
        if(inet_pton(AF_INET, remote_str, &pe->ft.remote))
            inet_pton(AF_INET, "255.255.255.255", &pe->remote_netmask);
        else
            strncpy(pe->remote, remote_str, sizeof(pe->remote));
    }

    //--REMOTE NETMASK--//
    value = json_object_object_get(jobj_policy, "remote_netmask");
    if(value != NULL && json_object_is_type(value, json_type_string)) {
        const char * remote_net_str = json_object_get_string(value);
        inet_pton(AF_INET, remote_net_str, &pe->remote_netmask);
        pe->ft.remote &= pe->remote_netmask;
    }

    //--LOCAL PORT--//
    value = json_object_object_get(jobj_policy, "remote_port");
    if(value != NULL && json_object_is_type(value, json_type_int)) {
        pe->ft.remote_port = json_object_get_int(value);
    }

    //--RATE LIMIT--//
    value = json_object_object_get(jobj_policy, "rate_limit");
    if(value != NULL) {
        if(json_object_is_type(value, json_type_double))
            pe->rate_limit = json_object_get_double(value);
        else if(json_object_is_type(value, json_type_int))
            pe->rate_limit = json_object_get_int(value);

    }

    return SUCCESS;
failure_print:
    DEBUG_MSG("Failed to parse policy %s", json_object_to_json_string(jobj_policy));
    return FAILURE;
}

int match_policy(struct flow_tuple *ft, policy_entry *policy, int dir) {
        if((policy->direction & dir) == 0) { return 0; }

        if(strlen(policy->local) > 0) {
            if(strcmp(policy->local, "self") == 0 && ft->local != getTunnel()->n_private_ip) { return 0; }
        }
        else if(policy->ft.local != (ft->local & policy->local_netmask)) { return 0; }

        if(strlen(policy->remote) > 0) {
            if(strcmp(policy->remote, "self") == 0 && ft->remote != getTunnel()->n_private_ip) { return 0; }
        }
        else if(policy->ft.remote != (ft->remote & policy->remote_netmask)) { return 0; }

        if((policy->ft.proto != 0) && policy->ft.proto != ft->proto) { return 0; }
        return 1;
}

int get_policy_by_tuple(struct flow_tuple *ft, policy_entry *policy, int dir) {
    if(!init) { DEBUG_MSG("Policy table must be initialized"); return FAILURE; }
    int count = policy_count;
    for(int i = 0; i < count; i++) {
        *policy = *policies[i];
        if(match_policy(ft, policy, dir))
            return SUCCESS;
    }

    *policy = *default_policy;
    return FAILURE;
}

static policy_entry** load_policies(int * count) {
    *count = 0;
    json_object * table = get_table();
    if(table == 0) {
        DEBUG_MSG("Policy table doesn't exist at /var/lib/wirover/policy_tbl");
        goto default_return;
    }
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
    free(table);
    return output;

free_return:
    free(output);
default_return:
    free(table);
    *count = 1;
    output = ( policy_entry **)malloc(sizeof( policy_entry));
    output[0] = alloc_policy();
    return output;
}

//---------DEBUG METHODS------------//

void print_policy_entry(policy_entry * pe) {
    char l_str[INET6_ADDRSTRLEN];
    if(strlen(pe->local) > 0)
        strncpy(l_str, pe->local, sizeof(l_str));
    else
        inet_ntop(AF_INET, &pe->ft.local, l_str, sizeof(l_str));

    char l_str_port[INET6_ADDRSTRLEN + 10];
    if(pe->ft.local_port != 0)
        snprintf(l_str_port, sizeof(l_str_port), "%s:%d", l_str, pe->ft.local_port);
    else
        snprintf(l_str_port, sizeof(l_str_port), "%s", l_str);

    char l_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->local_netmask, l_net_str, sizeof(l_net_str));

    char r_str[INET6_ADDRSTRLEN];
    if(strlen(pe->remote) > 0)
        strncpy(r_str, pe->remote, sizeof(r_str));
    else
        inet_ntop(AF_INET, &pe->ft.remote, r_str, sizeof(r_str));

    char r_str_port[sizeof(r_str) + 10];
    if(pe->ft.remote_port != 0)
        snprintf(r_str_port, sizeof(r_str_port), "%s:%d", r_str, pe->ft.remote_port);
    else
        snprintf(r_str_port, sizeof(r_str_port), "%s", r_str);

    char r_net_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &pe->remote_netmask, r_net_str, sizeof(r_net_str));

    char *dir_str;
    if(pe->direction == DIR_INGRESS) { dir_str = "I"; }
    if(pe->direction == DIR_EGRESS) { dir_str = "O"; }
    if(pe->direction == DIR_BOTH) { dir_str = "*"; }
    char link_pref_str[100];
    link_pref_str[0] = 0;
    if(pe->preferred_link[0] != 0){
        snprintf(link_pref_str, 100, " preferred link: %s", pe->preferred_link);
    }
    DEBUG_MSG("direction: %s local: %s local_net: %s remote: %s remote_net: %s proto: %d act: %d nat?: %d ls: %d%s rate: %f",
        dir_str, l_str_port, l_net_str, r_str_port, r_net_str, pe->ft.proto, pe->action, pe->allow_nat_failover, pe->link_select, link_pref_str, pe->rate_limit);
}

void print_policies() {
    DEBUG_MSG("Policies(%d):", policy_count);
    for(int i = 0; i < policy_count; i++){
        print_policy_entry(policies[i]);
    }
}
