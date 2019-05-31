// File: blacklist.c Author: Humbedooh A simple black-listing module for rumble. Created on January 3,
// 2011, 8:08
#include "../../rumble.h"

masterHandle * myMaster = NULL;
static const char * BL_L       = "BlackList"; // Mod name
static const char * _bl_conf   = "blacklist.conf"; // Mod config file

// I am sorry if you got here by accident.
char str_bad_hst[2048] = "HINET-IP.hinet.net dynamic.hinet.net dynamic.163data.com.cn dynamic.so-net.net.tw res.rr.com user.ono.com";
char str_bad_dom[2048] = "123.com myfirstmail.com delphi.com rocketmail.com juno.com fastmail.fm";
char str_dns_bl [2048] = "cbl.abuseat.org sbl.spamhaus.org dnsbl-1.uceprotect.net";
int  blacklist_spf = 0;
char str_logfile[512] = "/tmp/rumble-blacklist.log";

rumblemodule_config_struct  myConfig[] = {
    {"BlacklistByHost", 40, "List of servers that are blacklisted from contacting our SMTP server",  RCS_STRING, &str_bad_hst },
    {"BlacklistByMail", 40, "List of email domains that are by default invalid as sender addresses", RCS_STRING, &str_bad_dom },
    {"DNSBL",           40, "A list of DNSBL providers to use for querying",                         RCS_STRING, &str_dns_bl },
    {"EnableSPF",        1, "Should SPF records be checked?",                                       RCS_BOOLEAN, &blacklist_spf },
    {"Logfile",         24, "Optional location of a logfile for blacklist encounters",               RCS_STRING, &str_logfile },
    {0, 0, 0, 0 }
};

rumble_args  *blacklist_bad_hst = NULL;
rumble_args  *blacklist_bad_dom = NULL;
rumble_args  *blacklist_dns_bl = NULL;
const char   *blacklist_logfile = NULL;
cvector      *fastList = NULL;
dvector *configuration = NULL;

ssize_t bl_hook_domain(sessionHandle *session, const char *junk) {
    // Check against pre-configured list of bad hosts
    for (int i = 0; i < blacklist_bad_dom->argc; i++) {
        char *badhost = blacklist_bad_dom->argv[i];
        if (!strcmp(session->sender->domain, badhost)) {
            rumble_debug(myMaster, BL_L, "%s was blacklisted as a bad domain, aborting", badhost);
            rumble_comm_send(session, "530 Sender domain has been blacklisted.\r\n");
            if (blacklist_logfile) {
                FILE * fp = fopen(blacklist_logfile, "a");
                if (fp) {
                    time_t  rawtime;
                    time(&rawtime);
                    rumble_debug(myMaster, BL_L, "[%s] %s: Attempt to use %s as sender domain", ctime(&rawtime), session->client->addr, badhost);
                    fclose(fp);
                } else rumble_debug(myMaster, BL_L, "Error: Couldn't open: %s", blacklist_logfile);
            }
            return (RUMBLE_RETURN_IGNORE);
        }
    }
    return (RUMBLE_RETURN_OKAY);
}

typedef struct {
    time_t          when;
    unsigned int    IP[4];
} blackListEntry;

ssize_t bl_hook_newconn(sessionHandle *session, const char *junk) {
    masterHandle *SMH = (masterHandle*)session->_master;
    // Resolve client address name
    const char * addr;
    unsigned int a, b, c, d;
    // Check if the client has been given permission to skip this check by any other modules.
    if (session->flags & RUMBLE_SMTP_FREEPASS)
        return (RUMBLE_RETURN_OKAY);
    else {
        int x = 0;
        c_iterator iter;
        blackListEntry * entry;
        sscanf(session->client->addr, "%3u.%3u.%3u.%3u", &a, &b, &c, &d);

        // Check against the fast list of already encountered spammers
        cforeach((blackListEntry *), entry, fastList, iter) {
            x++;
            printf("checking fl rec no. %u\n", x);
            if (entry->IP[0] == a && entry->IP[1] == b && entry->IP[2] == c && entry->IP[3] == d) {
                time_t  now = time(NULL);

                if (now - entry->when > 86400) {
                    cvector_delete(&iter);
                    free(entry);
                } else {
                    rumble_debug(SMH, BL_L, "%s is listed in the fast list as a spam host.", session->client->addr);
                    return (RUMBLE_RETURN_FAILURE);

                }
            }
        }

        // ANSI method
        struct in6_addr IP;
        inet_pton(session->client->client_info.ss_family, session->client->addr, &IP);
        struct hostent * client = gethostbyaddr((char*) &IP, (session->client->client_info.ss_family == AF_INET) ? 4 : 16,
            session->client->client_info.ss_family);
        if (!client) return (RUMBLE_RETURN_IGNORE);
        addr = (const char *) client->h_name;
        rumble_string_lower((char *) addr);
    }

    for (int i = 0; i < blacklist_bad_hst->argc; i++) {
        // Check against pre-configured list of bad hosts
        char * badhost = blacklist_bad_hst->argv[i];
        if (strstr(addr, badhost)) {
            rumble_debug(SMH, BL_L, "%s was blacklisted as a bad host name, aborting", addr);
            if (blacklist_logfile) {
                FILE * fp = fopen(blacklist_logfile, "w+");
                if (fp) {
                    char * mtime = rumble_mtime();
                    rumble_debug(SMH, BL_L, "[%s] %s: %s is blacklisted as a bad host.", mtime, session->client->addr, addr);
                    fprintf(fp,                   "[%s] %s: %s is blacklisted as a bad host.", mtime, session->client->addr, addr);
                    fclose(fp);
                    free(mtime);
                } else rumble_debug(myMaster, BL_L, "Error: Couldn't open: %s", blacklist_logfile);
            }
            return (RUMBLE_RETURN_FAILURE);
        }
    }

    // Check against DNS blacklists
    if (session->client->client_info.ss_family == AF_INET) {
        // I only know how to match IPv4 DNSBL :/
        for (int i = i; i < blacklist_dns_bl->argc; i++) {
            char *dnshost = (char*) blacklist_dns_bl->argv[i];
            if (dnshost) { // crash protect
            char *dnsbl   = (char*) calloc(1, strlen(dnshost) + strlen(session->client->addr) + 6);
            if (dnsbl) {

                sprintf(dnsbl, "%d.%d.%d.%d.%s", d, c, b, a, dnshost);
                if (gethostbyname(dnsbl)) {
                    rumble_debug(SMH, BL_L, "%s was blacklisted by %s, closing connection!", session->client->addr, dnshost);
                    rumble_debug(SMH, BL_L, "Adding entry %u.%u.%u.%u to fl", a, b, c, d);
                    blackListEntry * entry = (blackListEntry *) malloc(sizeof(blackListEntry)); // TODO Check alloc
                    entry->when = time(NULL);
                    entry->IP[0] = a; entry->IP[1] = b; entry->IP[2] = c; entry->IP[3] = d;
                    cvector_add(fastList, entry);
                    if (blacklist_logfile) {
                        FILE * fp = fopen(blacklist_logfile, "a");
                        if (fp) {
                            char * mtime = rumble_mtime();
                            rumble_debug(SMH, BL_L, "[%s] %s: %s is blacklisted by DNSBL %s.", mtime, session->client->addr, addr, dnshost);
                            fprintf(fp,                   "[%s] %s: %s is blacklisted by DNSBL %s.", mtime, session->client->addr, addr, dnshost);
                            fclose(fp);
                            free(mtime);
                        } else rumble_debug(myMaster, BL_L, "Error: Couldn't open: %s", blacklist_logfile);
                    }
                    free(dnsbl);
                    return (RUMBLE_RETURN_FAILURE); // Blacklisted, abort the connection!
                }
                free(dnsbl);
            } // !dnsbl - no mem
            // !dnshost
            }
        } // next dnshost
    } // Check against DNS blacklists

    return (RUMBLE_RETURN_OKAY); // Return with EXIT_SUCCESS and let the server continue
}

const char * cfg_blob = "\
# %s\n%s  %s\n\n\
# %s\n%s  %s\n\n\
# %s\n%s  %s\n\n\
# %s\n%s  %d\n\n\
# %s\n%s  %s\n";


void bl_write_config(void) {
    const char *cfgpath = rumble_config_str(myMaster, "config-dir");
    char filename[1024];
    sprintf(filename, "%s/%s", cfgpath, _bl_conf);
    FILE *cfgfile = fopen(filename, "w");
    if (cfgfile) { fprintf(cfgfile, cfg_blob,
        myConfig[0].description, myConfig[0].key, str_bad_hst,
        myConfig[1].description, myConfig[1].key, str_bad_dom,
        myConfig[2].description, myConfig[2].key, str_dns_bl,
        myConfig[3].description, myConfig[3].key, blacklist_spf,
        myConfig[4].description, myConfig[4].key, str_logfile
        );
        fclose(cfgfile);
    } else rumble_debug(myMaster, BL_L, "Error: Couldn't write <%s>", filename);
}


rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;
    fastList = cvector_init();
    modinfo->title       = "Blacklisting module";
    modinfo->description = "Standard blacklisting module for rumble.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    configuration = rumble_readconfig(_bl_conf);
    if (!configuration) {
        rumble_debug(myMaster, BL_L, "Can't open config <%s>, write defaults...", _bl_conf);
        bl_write_config();
    } else {
        const char *entry_BlacklistByHost = rumble_get_dictionary_value(configuration, myConfig[0].key); // Blacklisted hosts
        const char *entry_BlacklistByMail = rumble_get_dictionary_value(configuration, myConfig[1].key); // Blacklisted domain names
        const char *entry_BlacklistDNSBL  = rumble_get_dictionary_value(configuration, myConfig[2].key); // DNSBL providers
        const char *entry_EnableSPF       = rumble_get_dictionary_value(configuration, myConfig[3].key); // Enable SPF?
        const char *entry_Logfile         = rumble_get_dictionary_value(configuration, myConfig[4].key); // Log file
        if (!strcmp(entry_Logfile, "0")) entry_Logfile = NULL; // "0" for atoi !!!

        if (entry_BlacklistByHost) { memset(str_bad_hst, 0, 2048); strcpy(str_bad_hst, entry_BlacklistByHost); }
        if (entry_BlacklistByMail) { memset(str_bad_dom, 0, 2048); strcpy(str_bad_dom, entry_BlacklistByMail); }
        if (entry_BlacklistDNSBL)  { memset(str_dns_bl,  0, 2048); strcpy(str_dns_bl,  entry_BlacklistDNSBL); }
        blacklist_spf = atoi(entry_EnableSPF);
        if (entry_Logfile)         { memset(str_logfile, 0, 512); strcpy(str_logfile, entry_Logfile); blacklist_logfile = str_logfile;}
        else blacklist_logfile = NULL;
    }

    blacklist_bad_hst = rumble_read_words(str_bad_hst); // Blacklisted hosts
    blacklist_bad_dom = rumble_read_words(str_bad_dom); // Blacklisted domain names
    blacklist_dns_bl =  rumble_read_words(str_dns_bl);  // DNSBL providers

    rumble_debug(myMaster, BL_L, "  Blacklisted hosts=%d", blacklist_bad_hst->argc);
    rumble_debug(myMaster, BL_L, "Blacklisted domains=%d", blacklist_bad_dom->argc);
    rumble_debug(myMaster, BL_L, "  Blacklisted DNSBL=%d", blacklist_dns_bl->argc);

    if (blacklist_logfile) rumble_debug(myMaster, BL_L, "Set Log File=%s", blacklist_logfile);
    else rumble_debug(myMaster, BL_L, "Log File not set!");


    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_ACCEPT, bl_hook_newconn); // Hook the module to new connections.

    // If fake domain check is enabled, hook that one too
    if (blacklist_bad_dom->argc > 0)
        rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_CUE_SMTP_MAIL, bl_hook_domain);

    return (EXIT_SUCCESS); // Tell rumble that the module loaded okay
}

rumbleconfig rumble_module_config(const char *k, const char *v) {
    if (!k) return (myConfig);
    rumble_debug(myMaster, BL_L, "Config <key=value> <%s=%s>", k, v);
    if (!strcmp(k, myConfig[0].key) && v) { strcpy(str_bad_hst, v); blacklist_bad_hst = rumble_read_words(v); }
    if (!strcmp(k, myConfig[1].key) && v) { strcpy(str_bad_dom, v); blacklist_bad_dom = rumble_read_words(v); }
    if (!strcmp(k, myConfig[2].key) && v) { strcpy(str_dns_bl,  v); blacklist_dns_bl  = rumble_read_words(v); }
    if (!strcmp(k, myConfig[3].key)) { blacklist_spf = atoi(v); }
    if (!strcmp(k, myConfig[4].key) && v) {
        strcpy(str_logfile, v);
        if (!strlen(v)) blacklist_logfile = NULL; else blacklist_logfile = str_logfile;
    }
    bl_write_config();
    return (NULL);
}

