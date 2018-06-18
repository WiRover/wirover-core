#include <arpa/inet.h>
#include <json/json.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "version.h"


struct wirover_version *version = NULL;
/*
 * Fill in wirover_version structure with data in network byte order.
 */
struct wirover_version get_wirover_version()
{
    if(version == NULL)
    {
        char *version_path;
    #ifdef GATEWAY
        version_path = WIROVER_VAR_DIR "/wigateway_version";
    #endif
    #ifdef ROOT
        version_path = WIROVER_VAR_DIR "/wiroot_version";
    #endif
    #ifdef CONTROLLER
        version_path = WIROVER_VAR_DIR "/wicontroller_version";
    #endif
        char * buffer = 0;
        long length;
        FILE * f = fopen (version_path, "rb");

        version = (struct wirover_version *)malloc(sizeof(struct wirover_version));
        memset(version, 0, sizeof(struct wirover_version));

        if(f != 0) {
            fseek (f, 0, SEEK_END);
            length = ftell (f);
            fseek (f, 0, SEEK_SET);
            buffer = malloc (length + 1);
            if (buffer)
            {
                buffer[length] = 0;
                fread (buffer, 1, length, f);
                json_object * table = json_tokener_parse(buffer);
                if(json_object_is_type(table, json_type_object)) {
                    json_object *version_obj = json_object_object_get(table, "version");
                    if(json_object_is_type(version_obj, json_type_string)) {
                        char *version_str = (char *)json_object_get_string(version_obj);
                        char *split;
                        split = strtok(version_str, ".");
                        version->major = strtol(split, (char **)NULL, 10);
                        version->minor = strtol(strtok(NULL, "."), (char **)NULL, 10);
                        version->revision = strtol(strtok(NULL, "."), (char **)NULL, 10);
                    }
                }
            }
            fclose (f);
        }
    }
    return *version;
}

uint8_t get_tunnel_version() {
    struct wirover_version version = get_wirover_version();
    return version.major + version.minor + version.revision;
}

int compare_wirover_version(struct wirover_version comp) {
    struct wirover_version version = get_wirover_version();
    if(comp.major > version.major) { return 1; }
    if(comp.major < version.major) { return -1; }
    if(comp.minor > version.minor) { return 1; }
    if(comp.minor < version.minor) { return -1; }
    if(comp.revision > version.revision) { return 1; }
    if(comp.revision < version.revision) { return -1; }
    return 0;
}
