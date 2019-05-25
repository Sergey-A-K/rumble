// greylist.c Author: Humbedooh A simple grey-listing module for rumble

#include "../../rumble.h"
#include <string.h>

int           GREYLIST_MAX_AGE = 432000;  // Grey-list records will linger for 5 days.
int           GREYLIST_MIN_AGE = 599;     // Put new triplets on hold for 10 minutes
int           GREYLIST_ENABLED = 1;       // 1 = yes, 0 = no

dvector      *configuration;
masterHandle *myMaster = 0;
cvector      *rumble_greyList;

rumblemodule_config_struct  myConfig[] =
{
    { "quarantine", 3, "How long are new email triplets held back (seconds)", RCS_NUMBER, &GREYLIST_MIN_AGE },
    { "linger", 6, "How long should I keep triplets stored? (seconds)", RCS_NUMBER, &GREYLIST_MAX_AGE },
    { "enabled", 1, "Enable mod_greylist?", RCS_BOOLEAN, &GREYLIST_ENABLED },
    { 0, 0, 0, 0 }
};

typedef struct
{
    char    *what;
    time_t  when;
} rumble_triplet;


ssize_t rumble_greylist(sessionHandle *session, const char *junk) {
    if (!GREYLIST_ENABLED) return (RUMBLE_RETURN_OKAY);
    // First, check if the client has been given permission to skip this check by any other modu
    if (session->flags & RUMBLE_SMTP_FREEPASS) return (RUMBLE_RETURN_OKAY);
    // Create the SHA1 hash that corresponds to the triplet.
    address * recipient = session->recipients->size ? (address *) session->recipients->first : 0;
    if (!recipient) {
        rumble_debug(NULL, "module", "<greylist> No recipients found! (server bug?)");
        return (RUMBLE_RETURN_FAILURE);
    }

    // Truncate the IP address to either /24 for IPv4 or /64 for IPv6
    char * block = (char*) calloc(1, 20); // TODO Chec mem
    if (!strchr(session->client->addr, ':')) {
        unsigned int a, b, c;

        sscanf(session->client->addr, "%3u.%3u.%3u", &a, &b, &c);
        sprintf(block, "%03u.%03u.%03u", a, b, c);
    } else strncpy(block, session->client->addr, 19);   // IPv6
    char * tmp = (char*) calloc(1, strlen(session->sender->raw) + strlen(junk) + strlen(block) + 1); // TODO Chec mem
    sprintf(tmp, "%s%s%s", session->sender->raw, junk, block);
    char * str = rumble_sha256(tmp);
    free(tmp);
    free(block);
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

    // If no such triplet, create one and add it to the vector.
    if (n == -1) {
        rumble_triplet  *New = (rumble_triplet *) malloc(sizeof(rumble_triplet)); // TODO Chec mem
        New->what = str;
        New->when = now;
        cvector_add(rumble_greyList, New);
        n = 0;
    } else free(str);

    // If the check failed, we tell the client to hold off for 15 minutes.
    if (n < GREYLIST_MIN_AGE) {
        rumble_comm_printf(session, "451 4.7.1 Grey-listed for %u seconds. See http://www.greylisting.org\r\n", GREYLIST_MIN_AGE - n);
        rumble_debug(NULL, "module", "Mail from %s for %s greylisted for %u seconds.", session->client->addr, junk, GREYLIST_MIN_AGE - n);
        ((rumbleService *) session->_svc)->traffic.rejections++;
        session->client->rejected = 1;
        return (RUMBLE_RETURN_IGNORE);  // Tell rumble to ignore the command quietly.
    }

    // Otherwise, we just return with EXIT_SUCCESS and let the server continue.
    return (RUMBLE_RETURN_OKAY);
}


rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    modinfo->title = "Greylisting module";
    modinfo->description = "Standard greylisting module for rumble.\nAdds a 10 minute quarantine on unknown from-to combinations to prevent spam.";
    modinfo->author = "Humbedooh [humbedooh@users.sf.net]";
    rumble_greyList = cvector_init();
    printf("Reading config...\n");
    configuration = rumble_readconfig("greylist.conf"); // TODO Check handle and warning
    printf("done!\n");
    GREYLIST_MIN_AGE = atoi(rumble_get_dictionary_value(configuration, "quarantine"));
    GREYLIST_MAX_AGE = atoi(rumble_get_dictionary_value(configuration, "linger"));
    GREYLIST_ENABLED = atoi(rumble_get_dictionary_value(configuration, "enabled"));
    myMaster = (masterHandle *) master;

    // Hook the module to the DATA command on the SMTP server.
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_RCPT, rumble_greylist);
    return (EXIT_SUCCESS);  // Tell rumble that the module loaded okay.
}

// rumble_module_config: Sets a config value or retrieves a list of config values.

rumbleconfig rumble_module_config(const char *key, const char *value) {
    if (!key) return (myConfig);
    value = value ? value : "(null)";
    if (!strcmp(key, "quarantine")) GREYLIST_MIN_AGE = atoi(value);
    if (!strcmp(key, "linger")) GREYLIST_MAX_AGE = atoi(value);
    if (!strcmp(key, "enabled")) GREYLIST_ENABLED = atoi(value);
    const char * cfgpath = rumble_config_str(myMaster, "config-dir");
    char filename[1024]; // Max path?
    sprintf(filename, "%s/greylist.conf", cfgpath);
    FILE * cfgfile = fopen(filename, "w");
    if (cfgfile) {
        fprintf(cfgfile,
            "# Greylisting configuration. Please use RumbleLua to change these settings.\nQuarantine %u\nLinger %u\nEnabled %u\n",
            GREYLIST_MIN_AGE, GREYLIST_MAX_AGE, GREYLIST_ENABLED);
        fclose(cfgfile);
    } // TODO Check handle

    return NULL;
}
