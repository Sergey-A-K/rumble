// Author: Humbedooh A simple white-listing module for rumble.
// Created on January 3, 2011, 8:0

#include <string.h>
#include "../../rumble.h"

cvector      *rumble_whiteList;
masterHandle *myMaster;
const char * _w_List = "whiteList";


ssize_t rumble_whitelist(sessionHandle *session, const char *junk) {
    char *ip = (char*) malloc(strlen(session->client->addr) + 2);
    if (ip) {
        sprintf(ip, "%s.", session->client->addr);
        c_iterator iter;
        const char * addr;
        // Go through the list of white-listed spaces and see what we find.
        cforeach((const char *), addr, rumble_whiteList, iter) {
            if (!strncmp(addr, ip, strlen(addr))) {
                // Set the whitelist flag if the client matches a range.
                session->flags |= RUMBLE_SMTP_WHITELIST;
                break;
            }
        }
        free(ip);
    }
    return (RUMBLE_RETURN_OKAY); // Return with RUMBLE_RETURN_OKAY and let the server continue.
}

// rumble_debug(myMaster, _w_List, "LibGCRYPT version mismatch!");
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle*) master;
    modinfo->title       = "Whitelisting module";
    modinfo->description = "Standard whitelisting module for rumble. Allows SMTP traffic from "
        "pre-defined known email servers to pass through without having to go through greylisting first.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    rumble_whiteList = cvector_init();
    if (!rumble_whiteList) return (EXIT_FAILURE);
    char cfgfile[200];
    memset(cfgfile, 0, 200);
    sprintf(cfgfile, "%s/whitelist.conf", ((masterHandle*) master)->cfgdir);
    FILE * config = fopen(cfgfile, "r");
    int counter = 0;
    if (config) {
        char *buffer = (char*) malloc(200);
        if (buffer) {
            while (!feof(config)) {
                memset(buffer, 0, 200);
                fgets(buffer, 200, config);
                if (!ferror(config)) { // Return the error indicator
                    char * address = (char*) calloc(1, 46);
                    if (address) {
                        sscanf(buffer, "%46[^# \t\r\n]", address);
                        if (strlen(address)) {
                            char * el = (char*) calloc(1, strlen(address) + 2);
                            if (el) {
                                sprintf(el, "%s.", address); // add a trailing dot for security measures
                                cvector_add(rumble_whiteList, el);
                                counter++;
                            }
                        }
                        free(address);
                    }
                }
            }
            free(buffer);
        }
        fclose(config);
    } else {
        rumble_debug(myMaster, _w_List, "ERROR: Could not read <%s>", cfgfile);
        return (EXIT_FAILURE);
     }
    // Hook the module to new connections.
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_ACCEPT, rumble_whitelist);
    rumble_debug(myMaster, _w_List, "Loaded file <%s> contains %d [OK]", cfgfile, counter);
    return (EXIT_SUCCESS); // Tell rumble that the module loaded okay
}
