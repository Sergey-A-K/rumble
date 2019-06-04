// greylist.c Author: Humbedooh A simple grey-listing module for rumble

#include "../../rumble.h"
#include <string.h>


#define LOG(x ...) rumble_debug(myMaster, _g_l, x);
// #define LOG(x ...)


masterHandle *myMaster = NULL;
cvector      *rumble_GL;

const char * _g_l = "GreyList";
const char * gl_cfg = "greylist.conf";
const char * cfg_blob = "\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n";

int GL_ENABLED = 1;
int GL_MIN_AGE = 599;
int GL_MAX_AGE = 432000;

rumblemodule_config_struct  myConfig[] = {
    { "Enabled",    1, "Enable Greylisting? (def yes=1, no=0)",                         RCS_BOOLEAN, &GL_ENABLED },
    { "Quarantine", 3, "How long are new email triplets held back (seconds, def 599)",  RCS_NUMBER,  &GL_MIN_AGE },
    { "Linger",     6, "How long should I keep triplets stored? (seconds, def 432000)", RCS_NUMBER,  &GL_MAX_AGE },
    { 0, 0, 0, 0 }
};

typedef struct {
    char    *what;
    time_t  when;
} rumble_triplet;


ssize_t rumble_greylist(sessionHandle *session, const char *junk) {
    if (!GL_ENABLED) { return (RUMBLE_RETURN_OKAY); }
    // First, check if the client has been given permission to skip this check by any other modu
    if (session->flags & RUMBLE_SMTP_FREEPASS) {
        LOG("permission RUMBLE_SMTP_FREEPASS return OKAY");
        return (RUMBLE_RETURN_OKAY);
    }

    // Create the SHA1 hash that corresponds to the triplet.
    address * recipient = session->recipients->size ? (address *) session->recipients->first : 0;
    if (!recipient) {
        LOG("No recipients found! (server bug?)");
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
    cforeach((rumble_triplet *), item, rumble_GL, iter) {
        if (!strcmp(item->what, str)) {
            n = now - item->when;
            break;
        }

        // If the record is too old, delete it from the vector.
        if ((now - item->when) > GL_MAX_AGE) {
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
            cvector_add(rumble_GL, New);
        } else free(str); // No MEM
        n = 0;
    } else free(str);

    if (n < GL_MIN_AGE) { // If the check failed, we tell the client to hold off for 15 minutes.
        rumble_comm_printf(session, "451 4.7.1 Grey-listed for %u seconds. See http://www.greylisting.org\r\n", GL_MIN_AGE - n);
        LOG("module", "Mail from %s for %s greylisted for %u seconds.", session->client->addr, junk, GL_MIN_AGE - n);
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
            , myConfig[0].description, myConfig[0].key, GL_ENABLED
            , myConfig[1].description, myConfig[1].key, GL_MIN_AGE
            , myConfig[2].description, myConfig[2].key, GL_MAX_AGE
        );
        fclose(cfgfile);
    } else LOG("Error: Couldn't open <%s> for writing", filename);
}

rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;

    modinfo->title       = "Greylisting module";
    modinfo->description = "Standard greylisting module for rumble. Adds a 10 minute quarantine on unknown from-to combinations to prevent spam.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    dvector *configuration = rumble_readconfig(gl_cfg);
    if (!configuration) {
        LOG("Configuration not set, write defaults...");
        gl_write_config();
    } else {
        GL_ENABLED = atoi(rumble_get_dictionary_value(configuration, myConfig[0].key));
        GL_MIN_AGE = atoi(rumble_get_dictionary_value(configuration, myConfig[1].key));
        GL_MAX_AGE = atoi(rumble_get_dictionary_value(configuration, myConfig[2].key));
    }
    LOG("%s=%d, %s=%d, %s=%d",
        myConfig[0].key, GL_ENABLED, myConfig[0].key, GL_MIN_AGE, myConfig[0].key, GL_MAX_AGE);
    rumble_GL = cvector_init();
    // Hook the module to the DATA command on the SMTP server.
    rumble_hook_function(master,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_RCPT, rumble_greylist);

    return (EXIT_SUCCESS);  // Tell rumble that the module loaded okay.
}


// rumble_module_config: Sets a config value or retrieves a list of config values.
rumbleconfig rumble_module_config(const char *key, const char *value) {
    if (!key) return (myConfig);
    LOG("Module config: %s=%s", key, value);
    value = value ? value : "0";
    if (!strcmp(key, myConfig[0].key) && value) GL_ENABLED = atoi(value);
    if (!strcmp(key, myConfig[1].key) && value) GL_MIN_AGE = atoi(value);
    if (!strcmp(key, myConfig[2].key) && value) GL_MAX_AGE = atoi(value);
    gl_write_config();
    return (NULL);
}
