// File: public.c Author: Humbedooh Created on January 7, 2011, 11:27 PM
#include "rumble.h"


dvector         *debugLog = 0;
char            shutUp = 0;

// This file contains public functions for rumble (usable by both server and modules
void rumble_args_free(rumble_args *d) {
    if (!d) return;
    if (d->argc && d->argv) {
        for (uint32_t p = 0; p < d->argc; p++) {
            if (d->argv[p]) free(d->argv[p]);
        }
    }
    free(d->argv);
    free(d);
}

rumble_args *rumble_read_words(const char *d) {
    char        *s;
    rumble_args *ret = (rumble_args *) malloc(sizeof(rumble_args));
    ret->argv = (char **) calloc(1, 32 * sizeof(char *));
    ssize_t a = 0;
    ssize_t b = 0;
    ssize_t c = 0;
    ssize_t x = 0;
    ret->argc = 0;
    if (!d || !strlen(d)) {
        free(ret->argv);
        ret->argv = 0;
        return (ret);
    }

    for (s = (char *) d; *s; s++) {
        b++;
        if (*s == '"') c++;
        if (c % 2 == 0 && *s == ' ') {
            x = (*(d + a) == '"') ? 1 : 0;
            if (b - a - x - 1 > 0) {
                ret->argv[ret->argc] = (char *) calloc(1, b - a - x + 1);
                strncpy(ret->argv[ret->argc++], d + a + x, b - a - x - x - 1);
            }

            a = b;
        }
    }

    if (b > a) {
        x = (*(d + a) == '"') ? 1 : 0;
        if (b - a - x - 1 > 0) {
            ret->argv[ret->argc] = (char *) calloc(1, b - a - x + 1);
            strncpy(ret->argv[ret->argc++], d + a + x, b - a - x - x);
        }
    }

    return (ret);
}


rumble_args *rumble_splitstring(const char *d, char delimiter) {
    char        *s;
    rumble_args *ret = (rumble_args *) malloc(sizeof(rumble_args));

    ssize_t i = strlen(d);
    ret->argv = (char **) calloc(1, 32 * sizeof(char *));
    ssize_t a = 0;
    ssize_t b = 0;
    ssize_t c = 0;
    ssize_t x = 0;
    ret->argc = 0;
    if (!d || !strlen(d)) return (ret);

    char * buffer = (char *) malloc(i + 2);

    strncpy(buffer, d, i);

    buffer[i] = ' ';
    buffer[i + 1] = 0;
    for (s = (char *) buffer; *s; s++) {
        b++;
        if (*s == '"') c++;
        if (c % 2 == 0 && *s == delimiter) {
            x = (*(buffer + a) == '"') ? 1 : 0;
            if (b - a - x - 1 > 0) {
                ret->argv[ret->argc] = (char *) calloc(1, b - a - x + 1);
                strncpy(ret->argv[ret->argc++], buffer + a + x, b - a - x - x - 1);
            }

            a = b;
        }
    }

    if (b > a) {
        x = (*(buffer + a) == '"') ? 1 : 0;
        if (b - a - x - 1 > 0) {
            ret->argv[ret->argc] = (char *) calloc(1, b - a - x + 1);
            strncpy(ret->argv[ret->argc++], buffer + a + x, b - a - x);
        }
    }

    free(buffer);
    return (ret);
}


void rumble_scan_ranges(rangePair *ranges, const char *line) {
    if (!line) return;
    rumble_args * rangeList = rumble_splitstring(line, ',');
    uint32_t y = 0;
    for (uint32_t x = 0; x < rangeList->argc; x++) {
        size_t first = 0;
        size_t last = 0;
        if (sscanf(rangeList->argv[x], "%lu:%1[*]", &first, (char *) &last) == 2) {
            last = -1;
        } else if (sscanf(rangeList->argv[x], "%lu:%lu", &first, &last)) { } else {
            sscanf(rangeList->argv[x], "%lu", &first);
        }

        if (last == 0) last = first;
        if (first && last) {
            ranges[y].start = first;
            ranges[y].end = last;
            y++;
            if (y == 63) break;
        }
    }
    ranges[y].start = 0;
    rumble_args_free(rangeList);
}


address *rumble_parse_mail_address(const char *addr) {
    address *usr = (address *) malloc(sizeof(address));

    if (!usr) merror();
    if (!addr) return (0);
    usr->flags  = dvector_init();
    usr->domain = (char*)calloc(1, 130);
    usr->user   = (char*)calloc(1, 130);
    usr->raw    = (char*)calloc(1, 256);
    usr->tag    = (char*)calloc(1, 130);
    usr->_flags = (char*)calloc(1, 130);
    char * tmp  = (char*)calloc(1, 260);
    if (!tmp) merror();
    if (strchr(addr, '<')) {
        addr = strchr(addr, '<');

        // First, try to scan for "<user@domain> FLAGS"
        if (sscanf(addr, "<%256[^@ ]@%128[^>]>%128[A-Z= %-]", tmp, usr->domain, usr->_flags) < 2) {
            // Then, try scanning for "<> FLAGS" (bounce message)
            sscanf(addr, "<%128[^>]>%128[A-Z= %-]", tmp, usr->_flags);
        }

        // Parse any flags we find
        if (strlen(usr->_flags)) rumble_scan_flags(usr->flags, usr->_flags);

        // Separate username and VERP/BATV tag (if any)
        if (sscanf(tmp, "prvs=%16[^+=]=%128c", usr->tag, usr->user) < 2) {

            // Did we have a BATV tag?
            if (sscanf(tmp, "%128[^=]=%128c", usr->tag, usr->user) < 2) {

                // Or maybe a VERP?
                strncpy(usr->user, tmp, 128);   // Nope, just a username.
                memset(usr->tag, 0, 128);
            }
        }
    // Try plain old "mail from: user@domain" ?
    } else if (strlen(addr)) {
        if (strstr(addr, ": ")) addr = strstr(addr, ": ") + 2;
        else if (strchr(addr, ':'))
            addr = strchr(addr, ':') + 1;
        else addr = 0;
        if (addr) sscanf(addr, "%128[^@ ]@%128c", usr->user, usr->domain);
    }

    if (!strlen(usr->user) or!strlen(usr->domain)) {
        rumble_free_address(usr);
        usr = 0;
    } else sprintf(usr->raw, "<%s@%s> %s", usr->user, usr->domain, usr->_flags ? usr->_flags : "NOFLAGS");
    free(tmp);
    return (usr);
}


void rumble_string_lower(char *d) {
    size_t b = strlen(d);
    for (size_t a = 0; a < b; a++) {
        d[a] = (d[a] >= 'A' && d[a] <= 'Z') ? d[a] + 32 : d[a];
    }
}

void rumble_string_upper(char *d) {
    size_t b = strlen(d);
    for (size_t a = 0; a < b; a++) {
        d[a] = (d[a] >= 'a' && d[a] <= 'z') ? d[a] - 32 : d[a];
    }
}

// Scans a string for key=value pairs and stores them in a dvector dictionary.
void rumble_scan_flags(dvector *dict, const char *flags) {
    char    *pch = strtok((char *) flags, " ");
    char * key = (char *) calloc(1, 100);
    char * val = (char *) calloc(1, 100);
    while (pch != NULL) {
        if (strlen(pch) >= 3) {
            memset(key, 0, 99);
            memset(val, 0, 99);
            if (sscanf(pch, "%99[^=]=%99c", key, val) >= 1) {
                rumble_string_upper(key);
                rumble_add_dictionary_value(dict, key, val);
            }
        }
        pch = strtok(NULL, " ");
    }
    free(key);
    free(val);
}

// Scans a string for words and stores them in a dvector dictionary as [word] => 1
void rumble_scan_words(dvector *dict, const char *wordlist) {
    char    *key = (char *) calloc(1, 200);
    if (!key) merror();

    char    *pch = strtok((char *) wordlist, " ");
    while (pch != NULL) {
        strncpy(key, pch, 199);
        if (strlen(key) >= 1) {
            rumble_string_lower(key);
            rumble_add_dictionary_value(dict, key, "1");
        }
        pch = strtok(NULL, " ");
    }
    free(key);
}


const char *rumble_get_dictionary_value(dvector *dict, const char *flag) {
    dvector_element     *curr;
    for (curr = dict->first; curr != NULL; curr = curr->next) {
        rumbleKeyValuePair * el = (rumbleKeyValuePair *) curr->object;
        if (!strcmp(flag, el->key)) return (el->value);
    }
    return ("0");
}


uint32_t rumble_has_dictionary_value(dvector *dict, const char *flag) {
    dvector_element     *curr;
    for (curr = dict->first; curr != NULL; curr = curr->next) {
        rumbleKeyValuePair * el = curr->object;
        if (!strcmp(flag, el->key) && strlen(el->value)) return (1);
    }
    return (0);
}


void rumble_add_dictionary_value(dvector *dict, const char *key, const char *value) {
    char * nkey = (char *) calloc(1, strlen(key) + 1);
    char * nval = (char *) calloc(1, strlen(value) + 1);
    if (!nkey || !nval) merror();
    strcpy(nval, value);
    strcpy(nkey, key);
    rumbleKeyValuePair * el = (rumbleKeyValuePair *) malloc(sizeof(rumbleKeyValuePair));
    if (!el) merror();
    el->key = (const char *) nkey;
    el->value = (const char *) nval;
    dvector_add(dict, el);
}


void rumble_edit_dictionary_value(dvector *dict, const char *key, const char *value) {
    char                *nval;
    rumbleKeyValuePair  *el;
    rumbleKeyValuePair  *oel = 0;
    d_iterator          iter;
    dforeach((rumbleKeyValuePair *), el, dict, iter) {
        if (el->key && !strcmp(el->key, key)) {
            oel = el;
            break;
        }
    }
    if (oel && value) {
        if (oel->value) free((char *) oel->value);
        nval = (char *) calloc(1, strlen(value) + 1);
        strcpy(nval, value);
        oel->value = (const char *) nval;
    }
}


void rumble_delete_dictionary_value(dvector *dict, const char *key) {
    rumbleKeyValuePair  *el;
    d_iterator          iter;

    dforeach((rumbleKeyValuePair *), el, dict, iter) {
        if (el->key && !strcmp(el->key, key)) {
            if (el->value) free((char *) el->value);
            if (el->key) free((char *) el->key);
            break;
            dvector_delete(&iter);
        }
    }
}


void rumble_flush_dictionary(dvector *dict) {
    if (!dict) return;
    rumbleKeyValuePair  *el;
    d_iterator          iter;
    dforeach((rumbleKeyValuePair *), el, dict, iter) {
        if (el->key) free((char *) el->key);
        if (el->value) free((char *) el->value);
        free(el);
    }
    dvector_flush(dict);
}


void rumble_free_address(address *a) {
    if (!a) return;
    if (a->domain) free(a->domain);
    if (a->raw) free(a->raw);
    if (a->user) free(a->user);
    if (a->_flags) free(a->_flags);
    if (a->tag) free(a->tag);
    rumble_flush_dictionary(a->flags);
    dvector_destroy(a->flags);
    a->domain = 0;
    a->user = 0;
    a->raw = 0;
    a->_flags = 0;
    a->tag = 0;
    free(a);
}


char *rumble_mtime(void) {
    char    *txt = (char *) malloc(48);
    if (!txt) merror();
    time_t  rawtime;
    time(&rawtime);
    strftime(txt, 48, "%a, %d %b %Y %X +0000 (UTC)", gmtime(&rawtime));
    return (txt);
}

#if defined __x86_64__
#   define ptr2int(a)  (uint32_t) (((uintptr_t) a << 32))
#else
#   define ptr2int(a)  (uint32_t) a
#endif

char *rumble_create_filename(void) {
    uint32_t        y[4];
    char * name = (char *) malloc(17);
    y[0] = time(NULL) - rand();
    y[1] = rand() * rand();
    y[3] = ptr2int(rumble_create_filename) * rand();
    y[2] = ptr2int(&y) - rand();
    unsigned char   * p = (unsigned char *) y;
    for (uint8_t x = 0; x < 16; x++) {
        name[x] = (p[x] % 26) + 'a';
    }
    name[16] = 0;
    return (name);
}


size_t rumble_file_exists(const char *filename) {

    if (access(filename, 0) == 0) return (1);
    else return (0);
}


void rumble_vdebug(masterHandle *m, const char *svc, const char *msg, va_list args) {
    time_t          rawtime;
    struct tm       *timeinfo;
    dvector_element *obj;

    dvector * debug = m ? m->debug.logvector : debugLog;
    if (debug) {
        char * dstring = (char *) debug->last->object;
        obj = debug->last;
        obj->next = debug->first;
        obj->prev->next = 0;
        debug->last = obj->prev;
        debug->first->prev = obj;
        debug->first = obj;
        obj->prev = 0;
        time(&rawtime);
        timeinfo = gmtime(&rawtime);
        char dummy[512], txt[130];
        strftime(txt, 128, "%Y/%m/%d %X", timeinfo);
        sprintf(dummy, "%s [%s]: \t %s\n", txt, (svc ? svc : "core"), msg);
        vsnprintf(dstring, 511, dummy, args);
        printf("%s", dstring);
    } else {
        printf("rumble_vdebug called, but no debugLog exists!\n");
    }
}

void rumble_debug(masterHandle *m, const char *svc, const char *msg, ...) {
    va_list vl;
    dvector *debug;
    debug = m ? m->debug.logvector : debugLog;
    if (debug) {
        va_start(vl, msg);
        rumble_vdebug(m, svc, msg, vl);
    }
}

#ifdef RUMBLE_LUA

extern masterHandle * Master_Handle;

lua_State *rumble_acquire_state(void) {
    int             found = 0;
//     masterHandle    *master = Master_Handle;
    lua_State       *L = 0;
    pthread_mutex_lock(&Master_Handle->lua.mutex);
    for (int x = 0; x < RUMBLE_LSTATES; x++) {
        if (!Master_Handle->lua.states[x].working && Master_Handle->lua.states[x].state) {
            Master_Handle->lua.states[x].working = 1;
            //printf("Opened Lua state no. %u\n", x);
            L = (lua_State *) Master_Handle->lua.states[x].state;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&Master_Handle->lua.mutex);
    if (found) return (L);
    else {
        sleep(1);
        return (rumble_acquire_state());
    }
}

void rumble_release_state(lua_State *X) {
//     masterHandle    *master = Master_Handle;
    pthread_mutex_lock(&Master_Handle->lua.mutex);
    for (int x = 0; x < RUMBLE_LSTATES; x++) {
        if (Master_Handle->lua.states[x].state == X) {
            Master_Handle->lua.states[x].working = 0;
            //printf("Closed Lua state no. %u\n", x);
            break;
        }
    }
    pthread_mutex_unlock(&Master_Handle->lua.mutex);
}
#endif


char *strclone(const void *o) {
    size_t  l = strlen((const char *) o);
    char    *ret = calloc(1, l + 1);
    strncpy(ret, (const char *) o, l);
    return (ret);
}

