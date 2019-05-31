// File: spamassassin.c Author: Humbedooh Created on 13. june 2011, 20:11
#include "../../rumble.h"

#include "../../comm.h"
#include <errno.h>

const char * cfg_blob = "\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
<if compare(UseDaemon = 1)>\n\n\
  # %s\n  %s  %s\n\n\
  # %s\n  %s  %u\n\n\
<else>\n\n\
  # %s\n  %s  %s\n\n\
</if>\n";

masterHandle *myMaster;
dvector      *sa_config;

const char * _sp_ass        = "SpamAssassin";
const char * _sp_ass_cfg    = "spamassassin.conf";

const char samask[] = "%s/rumble-SA-XXXXXX";

int  sa_enabled        = 1;
int  sa_spamscore      = 5;
int  sa_modifyifspam   = 0;
int  sa_modifyifham    = 0;
int  sa_deleteifspam   = 1;
int  sa_usedaemon      = 1;
char sa_host[512]      = "localhost";
int  sa_port           = 783;
char sa_exec[512]      = "/usr/bin/spamassassin";

rumblemodule_config_struct  myConfig[] =
{
    { "Enabled",        2, "Should SpamAssassin be enabled on rumble?",                     RCS_BOOLEAN, &sa_enabled },
    { "SpamScore",      2, "At which score should emails be considered spam?",              RCS_NUMBER,  &sa_spamscore },
    { "ModifyIfSpam",   2, "Should SpamAssassin modify message headers if spam?",           RCS_BOOLEAN, &sa_modifyifspam },
    { "ModifyIfHam",    2, "Should SpamAssassin modify message headers if ham (non-spam)?", RCS_BOOLEAN, &sa_modifyifham },
    { "DeleteIfSpam",   2, "Should SpamAssassin delete spam?",                              RCS_BOOLEAN, &sa_deleteifspam },
    { "UseDaemon",      2, "Should we try the SA daemon process?",                          RCS_BOOLEAN, &sa_usedaemon },
    { "HostName",       16,"If using daemon, which port is it on?",                         RCS_STRING,  &sa_host },
    { "PortNumber",     3, "If using daemon, which port is it on?",                         RCS_NUMBER,  &sa_port },
    { "SpamExecutable", 32,"If not using the daemon, enter the name of the SpamAssassin executable to run instead", RCS_STRING, &sa_exec },
    { 0, 0, 0, 0 }
};

void sa_write_config(void) {
    const char * cfgpath = rumble_config_str(myMaster, "config-dir");
    char filename[1024];
    sprintf(filename, "%s/%s", cfgpath, _sp_ass_cfg);
    FILE *cfgfile = fopen(filename, "w");
    if (cfgfile) {
        fprintf(cfgfile, cfg_blob,  myConfig[0].description, myConfig[0].key, sa_enabled,
                                    myConfig[1].description, myConfig[1].key, sa_spamscore,
                                    myConfig[2].description, myConfig[2].key, sa_modifyifspam,
                                    myConfig[3].description, myConfig[3].key, sa_modifyifham,
                                    myConfig[4].description, myConfig[4].key, sa_deleteifspam,
                                    myConfig[5].description, myConfig[5].key, sa_usedaemon,
                                    myConfig[6].description, myConfig[6].key, sa_host,
                                    myConfig[7].description, myConfig[7].key, sa_port,
                                    myConfig[8].description, myConfig[8].key, sa_exec );
        fclose(cfgfile);
    } else rumble_debug(myMaster, _sp_ass, "Error: Couldn't open <%s> for writing", filename);
}

ssize_t sa_check(sessionHandle *session, const char *filename); // proto

rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;
    modinfo->title       = "SpamAssassin plugin";
    modinfo->description = "Enables support for SpamAssassin mail filtering.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    sa_config = rumble_readconfig(_sp_ass_cfg);
    if (!sa_config) {
        sa_write_config();
    } else {
        sa_enabled       = atoi(rumble_get_dictionary_value(sa_config, myConfig[0].key));
        sa_spamscore     = atoi(rumble_get_dictionary_value(sa_config, myConfig[1].key));
        sa_modifyifspam  = atoi(rumble_get_dictionary_value(sa_config, myConfig[2].key));
        sa_modifyifham   = atoi(rumble_get_dictionary_value(sa_config, myConfig[3].key));
        sa_deleteifspam  = atoi(rumble_get_dictionary_value(sa_config, myConfig[4].key));
        sa_usedaemon     = atoi(rumble_get_dictionary_value(sa_config, myConfig[5].key));
        strcpy(sa_host,         rumble_get_dictionary_value(sa_config, myConfig[6].key));
        sa_port          = atoi(rumble_get_dictionary_value(sa_config, myConfig[7].key));
        strcpy(sa_exec,         rumble_get_dictionary_value(sa_config, myConfig[8].key));
    }

    if (sa_enabled) {
        rumble_hook_function(myMaster, RUMBLE_HOOK_SMTP+RUMBLE_HOOK_COMMAND+RUMBLE_CUE_SMTP_DATA+RUMBLE_HOOK_AFTER,sa_check);
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(myMaster, _sp_ass, "%s=%d %s=%d %s=%d",
            myConfig[1].key, sa_spamscore, myConfig[2].key, sa_modifyifspam, myConfig[3].key, sa_modifyifham, myConfig[4].key, sa_deleteifspam);
        if (sa_usedaemon)
            rumble_debug(myMaster, _sp_ass, "%s %s:%s <%s:%d>", myConfig[5].key, myConfig[6].key, myConfig[7].key, sa_host, sa_port);
        else rumble_debug(myMaster, _sp_ass, "%s <%s>", myConfig[8].key, sa_exec);
#endif
        rumble_debug(myMaster, _sp_ass, "Added hooks. Init [OK]");
    } else {
        rumble_debug(myMaster, _sp_ass, "This module is currently disabled via <%s>!", _sp_ass_cfg);
        return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS); // Tell rumble that the module loaded okay.
}


rumbleconfig rumble_module_config(const char *key, const char *value) {
    if (!key) { return (myConfig); }
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(myMaster, _sp_ass, "Module config key|value <%s>|<%s>", key, value);
#endif
    if (!strcmp(key, myConfig[0].key) && value) sa_enabled      = atoi(value);
    if (!strcmp(key, myConfig[1].key) && value) sa_spamscore    = atoi(value);
    if (!strcmp(key, myConfig[2].key) && value) sa_modifyifspam = atoi(value);
    if (!strcmp(key, myConfig[3].key) && value) sa_modifyifham  = atoi(value);
    if (!strcmp(key, myConfig[4].key) && value) sa_deleteifspam = atoi(value);
    if (!strcmp(key, myConfig[5].key) && value) sa_usedaemon    = atoi(value);
    if (!strcmp(key, myConfig[6].key) && value) strcpy(sa_host, value);
    if (!strcmp(key, myConfig[7].key) && value) sa_port         = atoi(value);
    if (!strcmp(key, myConfig[8].key) && value) strcpy(sa_exec, value);
    sa_write_config();
    return (0);
}


ssize_t sa_check(sessionHandle *session, const char *filename) {
    char    buffer[2001];
    ssize_t ret = RUMBLE_RETURN_OKAY;
    if (!sa_enabled) return (RUMBLE_RETURN_OKAY);
    rumble_debug(myMaster, _sp_ass, "plugin is now checking <%s>", filename);
    rumble_comm_send(session, "250-Checking message...\r\n");
    FILE * fp = fopen(filename, "rb");
    if (!fp) {
        rumble_debug(myMaster, _sp_ass, "WARNING: Couldn't open <%s>", filename);
        return (RUMBLE_RETURN_OKAY);
    }
    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    rewind(fp);
    if (sa_usedaemon) { // Use the spamd server?
        sessionHandle   s;
        clientHandle    c;
        s.client = &c;
        s._svc = 0;
        rumble_debug(myMaster, _sp_ass, "connecting to spamd <%s:%d>...", sa_host, sa_port);
        c.socket = comm_open((masterHandle *) session->_master, sa_host, sa_port);
        c.tls_session = 0;
        c.tls_recv = 0;
        c.tls_send = 0;
        FD_ZERO(&c.fd);
        FD_SET(c.socket, &c.fd);
        if (c.socket) {
            rumble_debug(myMaster, _sp_ass, "connected to spamd, sending request");
            if (sa_modifyifham || (sa_modifyifspam && !sa_deleteifspam))
                rumble_comm_send(&s, "PROCESS SPAMC/1.5\r\n");
            else
                rumble_comm_send(&s, "CHECK SPAMC/1.5\r\n");
            rumble_comm_printf(&s, "Content-length: %u\r\n\r\n", fsize);
            while (!feof(fp) && fp) {
                memset(buffer, 0, 2001);
                size_t bread = fread(buffer, 1, 2000, fp);
                send(c.socket, buffer, bread, 0);
            }
            fclose(fp);
            if (c.socket) {
                int spam = 0;
                rumble_debug(myMaster, _sp_ass, "recieving response...");
                char * line = rumble_comm_read(&s);
                if (line) {
                    if (strstr(line, "EX_OK")) {
                        while (strlen(line) > 2) {
                            free(line);
                            line = rumble_comm_read(&s);
                            if (!line) break;
                            if (strstr(line, "Spam: True")) {
                                spam = 1;
                            }
                            if (strstr(line, "Spam: False")) {
                                spam = 0;
                            }
                        }
                        free(line);
                        rumble_debug(myMaster, _sp_ass, "the message is %s!", spam ? "SPAM" : "not spam");
                        if (spam && sa_deleteifspam) {
                            rumble_debug(myMaster, _sp_ass, "deleting <%s>", filename);
                            unlink(filename);
                            ret = RUMBLE_RETURN_FAILURE;
                        } else if ((!spam && sa_modifyifham) || (spam && sa_modifyifspam)) {
                            fp = fopen(filename, "wb");
                            if (!fp) {
                                rumble_debug(myMaster, _sp_ass, "couldn't open file <%s>", filename);
                                return (RUMBLE_RETURN_OKAY);
                            }
                            while ((line = rumble_comm_read(&s))) {
                                if (fwrite(line, strlen(line), 1, fp) != 1) break;
                            }
                            rumble_debug(myMaster, _sp_ass, "modified <%s>", filename);
                            fclose(fp);
                        }
                    } else free(line);
                } else {
                    rumble_debug(myMaster, _sp_ass, "Spamd hung up :(");
                }
            }
            if (c.socket) disconnect(c.socket);
        } else {
            fclose(fp);
            rumble_debug(myMaster, _sp_ass, "WARNING: unreachable <%s:%d>", sa_host, sa_port);
        }
    } else {
        int     spam = 0;

        rumble_debug(myMaster, _sp_ass, "running check...");
        fclose(fp);

        const char *storagefolder = rumble_config_str(myMaster, "storagefolder");
        char * tempfile = (char*) calloc(1, strlen(samask) + strlen(storagefolder) + 1);
        if (!tempfile) return (RUMBLE_RETURN_OKAY);

        memset(tempfile, 0, strlen(samask) + strlen(storagefolder) + 1);
        sprintf(tempfile, samask, storagefolder);
        int fd = mkstemp(tempfile);
        if(fd == -1){
            rumble_debug(myMaster, _sp_ass, "ERROR: mkstemp(%s):%s", tempfile, strerror(errno));
        } else {
            rumble_debug(myMaster, _sp_ass, "created temporary file <%s>", tempfile);
        }
        sprintf(buffer, "%s < %s > %s", sa_exec, filename, tempfile);
        rumble_debug(myMaster, _sp_ass, "executing: <%s>", buffer);
        system(buffer);
        fp = fopen(tempfile, "rb");
        rumble_debug(myMaster, _sp_ass, "unlink <%s>", tempfile);
        if (fp) {
            if (!fgets(buffer, 2000, fp)) memset(buffer, 0, 2001);
            while (strlen(buffer) > 2) {
                if (strstr(buffer, "X-Spam-Status: Yes")) { spam = 1; }
                if (strstr(buffer, "X-Spam-Status: No"))  { spam = 0; }
                if (!fgets(buffer, 2000, fp)) break;
            }
            fclose(fp);
        }
        rumble_debug(myMaster, _sp_ass, "the message is %s!", spam ? "SPAM" : "not spam");
        if (spam && sa_deleteifspam) {
            rumble_debug(myMaster, _sp_ass, "deleting <%s>", filename);
            unlink(filename);
            ret = RUMBLE_RETURN_FAILURE;
        } else if ((!spam && sa_modifyifham) || (spam && sa_modifyifspam)) {
            unlink(filename);
            rumble_debug(myMaster, _sp_ass, "moving modified file");
            if (rename(tempfile, filename)) {
                rumble_debug(myMaster, _sp_ass, "couldn't move <%s> to <%s> file :(", tempfile, filename);
            }
            rumble_debug(myMaster, _sp_ass, "unlink <%s>", tempfile);
            unlink(tempfile);
        }
    }
    return (ret);
}

