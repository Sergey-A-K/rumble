// greylist.c Author: Humbedooh A simple grey-listing module for rumble

#include "../../rumble.h"
#include <string.h>



dvector      *configuration;
masterHandle *myMaster = 0;
cvector      *rumble_greyList;

const char * _g_l = "GreyList";
const char * gl_cfg = "greylist.conf";
const char * cfg_blob = "\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n";

int GREYLIST_ENABLED = 1;
int GREYLIST_MIN_AGE = 599;
int GREYLIST_MAX_AGE = 432000;

rumblemodule_config_struct  myConfig[] = {
    { "Enabled",    1, "Enable Greylisting? (def yes=1, no=0)",                         RCS_BOOLEAN, &GREYLIST_ENABLED },
    { "Quarantine", 3, "How long are new email triplets held back (seconds, def 599)",  RCS_NUMBER,  &GREYLIST_MIN_AGE },
    { "Linger",     6, "How long should I keep triplets stored? (seconds, def 432000)", RCS_NUMBER,  &GREYLIST_MAX_AGE },
    { 0, 0, 0, 0 }
};

typedef struct {
    char    *what;
    time_t  when;
} rumble_triplet;


ssize_t rumble_greylist(sessionHandle *session, const char *junk) {
    if (!GREYLIST_ENABLED) {
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(myMaster, _g_l, "!GREYLIST_ENABLED return RUMBLE_RETURN_OKAY");
#endif
        return (RUMBLE_RETURN_OKAY);
    }
    // First, check if the client has been given permission to skip this check by any other modu
    if (session->flags & RUMBLE_SMTP_FREEPASS) {
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(myMaster, _g_l, "permission RUMBLE_SMTP_FREEPASS return RUMBLE_RETURN_OKAY");
#endif
        return (RUMBLE_RETURN_OKAY);
    }

    // Create the SHA1 hash that corresponds to the triplet.
    address * recipient = session->recipients->size ? (address *) session->recipients->first : 0;
    if (!recipient) {
        rumble_debug(myMaster, _g_l, "No recipients found! (server bug?)");
        return (RUMBLE_RETURN_FAILURE);
    }

    // Truncate the IP address to either /24 for IPv4 or /64 for IPv6
    char * block = (char*) calloc(1, 20);
    if (!block) return (RUMBLE_RETURN_FAILURE); // No MEM
    if (!strchr(session->client->addr, ':')) {
        unsigned int a, b, c;
        sscanf(session->client->addr, "%3u.%3u.%3u", &a, &b, &c);
        sprintf(block, "%03u.%03u.%03u", a, b, c);
    } else strncpy(block, session->client->addr, 19);   // IPv6
    char * tmp = (char*) calloc(1, strlen(session->sender->raw) + strlen(junk) + strlen(block) + 1);
    if (!tmp) { free(block); return (RUMBLE_RETURN_FAILURE); } // No MEM
    sprintf(tmp, "%s%s%s", session->sender->raw, junk, block);
    free(block);
    char * str = rumble_sha256(tmp);
    free(tmp);
    time_t n = -1;
    time_t now = time(0);
    rumble_triplet * item;
    c_iterator iter;

    // Run through the list of triplets we have and look for this one.
    cforeach((rumble_triplet *), item, rumble_greyList, iter) {
        if (!strcmp(item->what, str)) {
            n = now - item->when;
            break;
        }

        // If the record is too old, delete it from the vector.
        if ((now - item->when) > GREYLIST_MAX_AGE) {
            cvector_delete(&iter);
            free(item->what);
            free(item);
        }
    }

    if (n == -1) { // If no such triplet, create one and add it to the vector.
        rumble_triplet  *New = (rumble_triplet *) malloc(sizeof(rumble_triplet));
        if (New) {
            New->what = str;
            New->when = now;
            cvector_add(rumble_greyList, New);
        } else free(str); // No MEM
        n = 0;
    } else free(str);

    if (n < GREYLIST_MIN_AGE) { // If the check failed, we tell the client to hold off for 15 minutes.
        rumble_comm_printf(session, "451 4.7.1 Grey-listed for %u seconds. See http://www.greylisting.org\r\n", GREYLIST_MIN_AGE - n);
        rumble_debug(myMaster, _g_l, "module", "Mail from %s for %s greylisted for %u seconds.", session->client->addr, junk, GREYLIST_MIN_AGE - n);
        ((rumbleService *) session->_svc)->traffic.rejections++;
        session->client->rejected = 1;
        return (RUMBLE_RETURN_IGNORE);  // Tell rumble to ignore the command quietly.
    }

    // Otherwise, we just return with EXIT_SUCCESS and let the server continue.
    return (RUMBLE_RETURN_OKAY);
}


void gl_write_config(void) {
    const char * cfgpath = rumble_config_str(myMaster, "config-dir");
    char filename[1024];
    sprintf(filename, "%s/%s", cfgpath, gl_cfg);
    FILE *cfgfile = fopen(filename, "w");
    if (cfgfile) { fprintf(cfgfile, cfg_blob
            , myConfig[0].description, myConfig[0].key, GREYLIST_ENABLED
            , myConfig[1].description, myConfig[1].key, GREYLIST_MIN_AGE
            , myConfig[2].description, myConfig[2].key, GREYLIST_MAX_AGE
        );
        fclose(cfgfile);
    } else rumble_debug(myMaster, _g_l, "Error: Couldn't open <%s> for writing", filename);
}

rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;

    modinfo->title       = "Greylisting module";
    modinfo->description = "Standard greylisting module for rumble. Adds a 10 minute quarantine on unknown from-to combinations to prevent spam.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    configuration = rumble_readconfig(gl_cfg);
    if (!configuration) {
        rumble_debug(myMaster, _g_l, "Configuration not set, write defaults...");
        gl_write_config();
    } else {
        GREYLIST_ENABLED = atoi(rumble_get_dictionary_value(configuration, myConfig[0].key));
        GREYLIST_MIN_AGE = atoi(rumble_get_dictionary_value(configuration, myConfig[1].key));
        GREYLIST_MAX_AGE = atoi(rumble_get_dictionary_value(configuration, myConfig[2].key));
    }
    // Hook the module to the DATA command on the SMTP server.
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_RCPT, rumble_greylist);
    rumble_debug(myMaster, _g_l, "Added hooks. %s=%d, %s=%d, %s=%d [OK]", myConfig[0].key, GREYLIST_ENABLED, myConfig[0].key, GREYLIST_MIN_AGE, myConfig[0].key, GREYLIST_MAX_AGE);
    return (EXIT_SUCCESS);  // Tell rumble that the module loaded okay.
}


// rumble_module_config: Sets a config value or retrieves a list of config values.
rumbleconfig rumble_module_config(const char *key, const char *value) {
    if (!key) return (myConfig);
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(myMaster, _g_l, "Module config key|value <%s>|<%s>", key, value);
#endif
    value = value ? value : "0";
    if (!strcmp(key, myConfig[0].key) && value) GREYLIST_ENABLED = atoi(value);
    if (!strcmp(key, myConfig[1].key) && value) GREYLIST_MIN_AGE = atoi(value);
    if (!strcmp(key, myConfig[2].key) && value) GREYLIST_MAX_AGE = atoi(value);
    gl_write_config();
    return (NULL);
}
