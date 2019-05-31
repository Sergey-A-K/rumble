// This file is part of the Rumble Mail Server package.

#ifndef RUMBLE_H
#define RUMBLE_H


#define DBG_BIT00    0x00000001
#define DBG_BIT01    0x00000002
#define DBG_BIT02    0x00000004
#define DBG_BIT03    0x00000008
#define DBG_BIT04    0x00000010
#define DBG_BIT05    0x00000020
#define DBG_BIT06    0x00000040
#define DBG_BIT07    0x00000080
#define DBG_BIT08    0x00000100
#define DBG_BIT09    0x00000200
#define DBG_BIT10    0x00000400
#define DBG_BIT11    0x00000800
#define DBG_BIT12    0x00001000
#define DBG_BIT13    0x00002000
#define DBG_BIT14    0x00004000
#define DBG_BIT15    0x00008000
// modules
#define RUMBLE_DEBUG_COMM       0x00010000
#define RUMBLE_DEBUG_POP3         0x00020000
#define RUMBLE_DEBUG_SMTP         0x00040000
#define RUMBLE_DEBUG_IMAP         0x00080000
#define RUMBLE_DEBUG_HOOKS      0x00100000
#define RUMBLE_DEBUG_MODULES      0x00200000
#define DBG_BIT22               0x00400000
#define DBG_BIT23               0x00800000
#define DBG_BIT24               0x01000000
#define RUMBLE_DEBUG_THREADS    0x02000000
#define RUMBLE_DEBUG_STORAGE    0x04000000
#define RUMBLE_DEBUG_DATABASE   0x08000000
#define DBG_BIT28               0x10000000
#define DBG_BIT29               0x20000000
#define DBG_BIT30               0x40000000
#define DBG_BIT31               0x80000000


#ifndef RUMBLE_DEBUG
#define RUMBLE_DEBUG (RUMBLE_DEBUG_COMM | RUMBLE_DEBUG_POP3 | RUMBLE_DEBUG_SMTP | \
    RUMBLE_DEBUG_IMAP | RUMBLE_DEBUG_HOOKS | RUMBLE_DEBUG_MODULES | \
    RUMBLE_DEBUG_STORAGE | RUMBLE_DEBUG_DATABASE )
#endif



#include "rumble_version.h"

#define RUMBLE_INITIAL_THREADS  25
//
#ifdef __x86_64
#  define R_ARCH 64
#else
#  define R_ARCH 32
#endif

#define TRUE 1
#define FALSE 0

#ifndef __stdcall
#  define __cdecl
#  define __stdcall
#  define __fastcall
#endif

// INCLUDES
#include <stdio.h>

#include <string.h>
#include <time.h>


// POSIX headers
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <inttypes.h>
#include <pthread.h>

#include "cvector.h"

// Optional Lua support
#ifdef RUMBLE_LUA
#include "rumble_lua.h"
#endif

// RADB
#include "radb.h"


// ----------- FLAG DEFINITIONS -----------
// Module and function return codes
#   define RUMBLE_RETURN_OKAY      1 // Everything went fine, keep going.
#   define RUMBLE_RETURN_FAILURE   2 // Something went really wrong, abort the connection!
#   define RUMBLE_RETURN_IGNORE    3 // Module handled the return code, skip to next command.

// Flags for hooking modules to areas of rumble
#   define RUMBLE_HOOK_ACCEPT      0x00000001
#   define RUMBLE_HOOK_COMMAND     0x00000002
#   define RUMBLE_HOOK_EXIT        0x00000004
#   define RUMBLE_HOOK_FEED        0x00000008
#   define RUMBLE_HOOK_PARSER      0x00000010
#   define RUMBLE_HOOK_CLOSE       0x00000020
#   define RUMBLE_HOOK_STATE_MASK  0x000000FF
#   define RUMBLE_HOOK_SMTP        0x00000100
#   define RUMBLE_HOOK_POP3        0x00000200
#   define RUMBLE_HOOK_IMAP        0x00000400
#   define RUMBLE_HOOK_SVC_MASK    0x00000F00
#   define RUMBLE_HOOK_BEFORE      0x00000000
#   define RUMBLE_HOOK_AFTER       0x00001000
#   define RUMBLE_HOOK_TIMING_MASK 0x0000F000

// Flags for hooking modules to specific cues
#   define RUMBLE_CUE_SMTP_HELO    0x00010000
#   define RUMBLE_CUE_SMTP_RCPT    0x00020000
#   define RUMBLE_CUE_SMTP_MAIL    0x00040000
#   define RUMBLE_CUE_SMTP_DATA    0x00080000
#   define RUMBLE_CUE_SMTP_QUIT    0x00100000
#   define RUMBLE_CUE_SMTP_RSET    0x00200000
#   define RUMBLE_CUE_SMTP_NOOP    0x00400000
#   define RUMBLE_CUE_SMTP_VRFY    0x00800000
#   define RUMBLE_CUE_SMTP_AUTH    0x01000000
#   define RUMBLE_CUE_IMAP_AUTH    0x01000000
#   define RUMBLE_CUE_POP3_HELO    0x00010000
#   define RUMBLE_CUE_POP3_QUIT    0x00020000
#   define RUMBLE_CUE_POP3_TOP     0x00040000
#   define RUMBLE_CUE_POP3_RETR    0x00080000
#   define RUMBLE_CUE_POP3_LIST    0x00100000
#   define RUMBLE_CUE_POP3_DELE    0x00200000
#   define RUMBLE_CUE_POP3_PASS    0x01000000
#   define RUMBLE_CUE_MASK         0x0FFF0000


// Flags pertaining to SMTP sessions
#   define RUMBLE_SMTP_BADRFC      0x00000100   //Client is known to break RFC and requires leniency.
#   define RUMBLE_SMTP_WHITELIST   0x00000200   //Client has been whitelisted by a module.
#   define RUMBLE_SMTP_AUTHED      0x00000400   //Client is authenticated and considered known.
#   define RUMBLE_SMTP_CAN_RELAY   0x00000600   //Client is allowed to relay emails to other servers.
#   define RUMBLE_SMTP_FREEPASS    0x00000700   //Mask that covers all three exceptions.
#   define RUMBLE_SMTP_HAS_HELO    0x00000001   //Has valid HELO/EHLO
#   define RUMBLE_SMTP_HAS_MAIL    0x00000002   //Has valid MAIL FROM
#   define RUMBLE_SMTP_HAS_RCPT    0x00000004   //Has valid RCPT
#   define RUMBLE_SMTP_HAS_EHLO    0x00000009   //Has extended HELO
#   define RUMBLE_SMTP_HAS_BATV    0x00000010   //Has valid BATV signature

// Flags for POP3 sessions
#   define RUMBLE_POP3_HAS_USER    0x00000001   //Has provided a username (but no password)
#   define RUMBLE_POP3_HAS_AUTH    0x00000002   //Has provided both username and password

// Flags for IMAP4 sessions
#   define rumble_mailman_HAS_SELECT       0x00000001   //Has selected a mailbox
#   define rumble_mailman_HAS_TLS          0x00000002   //Has established TLS or SSL
#   define rumble_mailman_HAS_READWRITE    0x00000010   //Read/Write session (SELECT)
#   define rumble_mailman_HAS_READONLY     0x00000020   //Read-only session (EXAMINE)
#   define rumble_mailman_HAS_UID          0x00000100   //UID-type request.
#   define RUMBLE_ROAD_MASK                0x000000FF   //Command sequence mask

// Thread flags
#   define RUMBLE_THREAD_DIE       0x00001000   //Kill signal for threads
#   define RUMBLE_THREAD_MISC      0x00010000   //Thread handles miscellaneous stuff
#   define RUMBLE_THREAD_SMTP      0x00020000   //Thread handles SMTP
#   define RUMBLE_THREAD_POP3      0x00040000   //Thread handles POP3
#   define RUMBLE_THREAD_IMAP      0x00080000   //Thread handles IMAP
#   define RUMBLE_THREAD_SVCMASK   0x000F0000

// Mailbox type flags
#   define RUMBLE_MTYPE_MBOX   0x00000001   //Regular mailbox
#   define RUMBLE_MTYPE_ALIAS  0x00000002   //Alias to somewhere else
#   define RUMBLE_MTYPE_MOD    0x00000004   //Mail goes into a module
#   define RUMBLE_MTYPE_FEED   0x00000008   //Mail is fed to an external program or URL
#   define RUMBLE_MTYPE_RELAY  0x00000010   //Mail is being relayed to another server

// Letter flags (for POP3/IMAP4)
#   define RUMBLE_LETTER_RECENT    0x00000001
#   define RUMBLE_LETTER_UNREAD    0x00000010
#   define RUMBLE_LETTER_READ      0x00000020
#   define RUMBLE_LETTER_DELETED   0x00000100
#   define RUMBLE_LETTER_EXPUNGE   0x00000300
#   define RUMBLE_LETTER_ANSWERED  0x00001000
#   define RUMBLE_LETTER_FLAGGED   0x00010000
#   define RUMBLE_LETTER_DRAFT     0x00100000
#   define RUMBLE_LETTER_UPDATED   0x01000000
#   define RUMBLE_LETTER_SENT      0x10000000



// Domain flags
#   define RUMBLE_DOMAIN_NORELAY   0x00000001

// TYPE DEFINITIONS

typedef struct
{
    uint32_t        readers;
    uint32_t        writers;
    pthread_cond_t  reading;
    pthread_cond_t  writing;
    pthread_mutex_t mutex;
} rumble_readerwriter;


// New mailman structs
typedef struct
{
    uint32_t    inuse; // u8t ?
    uint64_t    id;
    uint32_t    flags;
    uint32_t    size;
    uint32_t    delivered;
    char        filename[32];
    uint32_t    updated;
} mailman_letter;

typedef struct
{
    char                name[65];
    uint64_t            fid;
    uint32_t            size;
    mailman_letter      *letters;
    uint32_t            firstFree;
    rumble_readerwriter *lock;
    uint32_t            subscribed;
    char                inuse;
} mailman_folder;

typedef struct
{
    uint32_t            uid;
    mailman_folder      *folders;
    uint32_t            size;
    rumble_readerwriter *lock;
    uint32_t            sessions;
    char                closed;
    uint32_t            firstFree;
    char                path[256];
} mailman_bag;

typedef struct rumblemodule_config_struct
{
    const char  *key;
    signed int  length;
    const char  *description;
    char        type;
    void        *value;
} rumblemodule_config_struct;

#define RCS_STRING  1
#define RCS_NUMBER  2
#define RCS_BOOLEAN 3
#define rumblemodule    int
#define rumbleconfig    rumblemodule_config_struct *

typedef int socketHandle;




#include <gnutls/gnutls.h>

#      define disconnect(a)   close(a)
typedef ssize_t (*dummyTLS_recv) (gnutls_session_t session, void *data, size_t data_size);
typedef ssize_t (*dummyTLS_send) (gnutls_session_t session, const void *data, size_t data_size);


typedef struct
{
    socketHandle            socket;
    struct sockaddr_storage client_info;
    char                    addr[46];
    fd_set                  fd;
    gnutls_session_t  tls_session; // int

    dummyTLS_recv tls_recv;   //Dummy operator for GNUTLS  gnutls_pull_func
    dummyTLS_send tls_send;   //Dummy operator for GNUTLS gnutls_push_func
    uint32_t                bsent;
    uint32_t                brecv;
    char                    rejected;
} clientHandle;

#   define RUMBLE_LSTATES  50

//     INTERNAL DOMAIN AND USER ACCOUNT STRUCTS

typedef struct
{
    char        *name;          //Name (or glob) of domain
    char        *path;          //Optional storage path for letters
    uint32_t    id;             //Domain ID
    uint32_t    flags;          //Domain flags
} rumble_domain;

typedef struct
{
    uint32_t        uid;
    char            *user;      //mailbox name
    rumble_domain   *domain;    //Pointer to domain struct
    uint32_t        type;       //type of mbox (mbox, alias, feed, mod)
    char            *arg;       //If it's of type alias, feed or mod, arg gives the args
    char            *hash;      //password hash
} rumble_mailbox;

//     ! Email address structure used by SMTP, POP3 and IMAP services

typedef struct _address
{
    char    *user;          //user
    char    *domain;        //domain name
    char    *raw;           //email address in raw format
    dvector *flags;         //BATV/VERP/Loop flags
    char    *_flags;        //Raw flags
    char    *tag;           //VERP or BATV tags
} address;

typedef struct
{
    dvector         *recipients;
    dvector         *dict;
    address         *sender;
    clientHandle    *client;
    uint32_t        flags;
    uint32_t        _tflags;
    uint32_t        bytes;
    void            *_master;
    void            *_svcHandle;
    void            *_svc;
} sessionHandle;

typedef struct
{
    const char  *title;
    const char  *description;
    const char  *author;
    const char  *file;
    rumblemodule_config_struct * (*config) (const char *key, const char *value);
} rumble_module_info;

typedef struct
{
    uint32_t    flags;
    ssize_t (*func) (sessionHandle *, const char *cmd);
    const char          *module;
    rumble_module_info  *modinfo;
#ifdef RUMBLE_LUA
    int                 lua_callback;
#endif
} hookHandle;

typedef struct
{
    struct __core
    {
        dvector     *conf;
        const char  *currentSO;
        dvector     *modules;
        cvector     *parser_hooks;
        cvector     *feed_hooks;
        radbMaster  *db;
        radbMaster  *mail;
        dvector     *batv;  //BATV handles for bounce control
        gnutls_certificate_credentials_t tls_credentials; // void*
        gnutls_priority_t tls_priority_cache; // void*
        gnutls_dh_params_t tls_dh_params;
        time_t      uptime;
    } _core;
    cvector *services;
    struct
    {
        rumble_readerwriter *rrw;
        dvector             *list;
    } domains;
    struct
    {
        rumble_readerwriter *rrw;
        dvector             *list;
        cvector             *bags;
    } mailboxes;
    const char  *cfgdir;
#ifdef RUMBLE_LUA
    struct
    {
        struct
        {
            int         working;
            lua_State   *state;
        } states[RUMBLE_LSTATES];
        pthread_mutex_t mutex;
    } lua;
#endif
    struct
    {
        FILE    *logfile;
        dvector *logvector;
    } debug;
} masterHandle;





typedef struct
{
    time_t      when;
    uint32_t    hits;
    uint32_t    bytes;
    uint32_t    rejections;
} traffic_entry;

typedef struct
{
    masterHandle    *master;
    socketHandle    socket;
    cvector         *threads;
    cvector         *init_hooks;
    cvector         *cue_hooks;
    cvector         *exit_hooks;
    cvector         *commands;
    cvector         *capabilities;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    dvector         *handles;
    dvector         *trafficlog;
    int             lua_handle;
    void * (*init) (void *);
    int enabled;
    struct
    {
        size_t  sent;
        size_t  received;
        size_t  sessions;
        size_t  rejections;
    } traffic;
    struct
    {
        const char      *port;
        const char      *name;
        int             threadCount;
        unsigned int    stackSize;
    } settings;
} rumbleService;

typedef struct
{
    pthread_t       thread;
    int             status;
    rumbleService   *svc;
} rumbleThread;

typedef struct
{
    char            svcName[1024];
    rumbleService   *svc;
} rumbleServicePointer;

typedef struct
{
    const char  *key;
    const char  *value;
} rumbleKeyValuePair;

typedef struct
{
    uint32_t    key;
    char        *value;
} rumbleIntValuePair;

typedef struct
{
    const char      *host;
    unsigned int    preference;
} mxRecord;

typedef struct
{
    address         *sender;
    address         *recipient;
    const char      *fid;
    const char      *flags;
    uint32_t        date;
    rumble_mailbox  *account;
    uint32_t        loops;
    char            mType;  //0 = regular mail, 1 = bounce
} mqueue;

typedef struct
{
    uint32_t    replyCode;
    char        *replyMessage;
    char        *replyServer;
    dvector     *flags;
} rumble_sendmail_response;

typedef struct
{
    uint64_t    id;         //Letter ID
    uint32_t    uid;        //User ID
    char        *fid;       //File ID
    uint32_t    size;       //Size of letter
    uint32_t    delivered;  //Time of delivery
    int64_t     folder;     //Folder name (for IMAP4)
    uint32_t    flags;      //Various flags
    uint32_t    _flags;     //Original copy of flags (for update checks)
} rumble_letter;

typedef struct
{
    cvector *headers;
    char    *body;
    int     is_multipart;
    int     is_last_part;
    cvector *multipart_chunks;
} rumble_parsed_letter;

typedef struct
{
    rumble_mailbox  *account;   //Pointer to account
    dvector         *contents;  //dvector with letters
    rumble_letter   **letters;  //post-defined array of letters for fast access
    uint32_t        size;       //Number of letters
} rumble_mailbag;

typedef struct
{
    uint32_t    id;
    char        *name;
    int         subscribed;
} rumble_folder;

typedef struct
{
    dvector             *folders;
    rumble_readerwriter *rrw;
    uint32_t            sessions;
    uint32_t            uid;
} rumble_mailman_shared_bag;

typedef struct
{
    int64_t                     id;
    time_t                      updated;
    uint64_t                    lastMessage;
    char                        *name;
    int                         subscribed;
    dvector                     *letters;
    rumble_mailman_shared_bag   *bag;
} rumble_mailman_shared_folder;

typedef struct
{
    char        **argv;
    uint32_t    argc;
} rumble_args;

typedef struct
{
    rumble_mailbox  *account;
    mailman_bag     *bag;
    mailman_folder  *folder;
} accountSession;

typedef ssize_t (*svcCommand) (masterHandle *, sessionHandle *, const char *, const char *);
typedef struct
{
    const char  *cmd;
    svcCommand  func;
} svcCommandHook;

typedef struct
{
    char    step;
    char    result;
    int     stepcount;
} base64_encodestate;

typedef struct
{
    uint64_t    start;
    uint64_t    end;
} rangePair;

//     FUNCTION PROTOTYPES


//     Functions for hooking modules into rumble

rumblemodule    rumble_module_check(void);
void            rumble_hook_function(void *handle, uint32_t flags, ssize_t (*func) (sessionHandle *, const char *));
void            rumble_service_add_command(rumbleService *svc, const char *command, svcCommand func);
void            rumble_service_add_capability(rumbleService *svc, const char *command);

//     Public tool-set

char                        *strclone(const void *o);



#ifdef RUMBLE_LUA
void                        rumble_loadscript(const char * script);
void                        rumble_release_state(lua_State *X);
lua_State                   *rumble_acquire_state(void);
#endif

size_t                      rumble_file_exists(const char *filename);
char                        *rumble_sha256(const char *d);  //SHA-256 digest (64 byte hex string)
char                        *rumble_decode_base64(const char *src);
char                        *rumble_encode_base64(const char *src, size_t len);
int                         rumble_unbase64(unsigned char *dest, const unsigned char *src, size_t srclen);
void                        rumble_string_lower(char *d);   //Converts <d> into lowercase.
void                        rumble_string_upper(char *d);   //Converts <d> into uppercase.
rumble_args                 *rumble_read_words(const char *d);
rumble_args                 *rumble_splitstring(const char *d, char delimiter);
void                        rumble_args_free(rumble_args *d);
void                        rumble_scan_ranges(rangePair *ranges, const char *line);
char                        *rumble_mtime(void);            //mail time
char                        *rumble_create_filename(void);  //Generates random 16-letter filenames
void                        rumble_scan_words(dvector *dict, const char *wordlist);
void                        rumble_scan_flags(dvector *dict, const char *flags);
void                        rumble_flush_dictionary(dvector *dict);
const char                  *rumble_get_dictionary_value(dvector *dict, const char *flag);
void                        rumble_add_dictionary_value(dvector *dict, const char *key, const char *value);
void                        rumble_edit_dictionary_value(dvector *dict, const char *key, const char *value);
void                        rumble_delete_dictionary_value(dvector *dict, const char *key);
uint32_t                    rumble_has_dictionary_value(dvector *dict, const char *flag);
void                        rumble_free_address(address *a);
void                        rumble_free_account(rumble_mailbox *user);
const char                  *rumble_smtp_reply_code(unsigned int code);
ssize_t                     rumble_comm_send(sessionHandle *session, const char *message);
ssize_t                     rumble_comm_send_bytes(sessionHandle *session, const char *message, size_t len);
ssize_t                     rumble_comm_printf(sessionHandle *session, const char *d, ...);
char                        *rumble_comm_read(sessionHandle *session);
char                        *rumble_comm_read_bytes(sessionHandle *session, int len);
const char                  *rumble_config_str(masterHandle *master, const char *key);
uint32_t                    rumble_config_int(masterHandle *master, const char *key);
void                        rumble_crypt_init(masterHandle *master);
address                     *rumble_parse_mail_address(const char *addr);
rumble_sendmail_response    *rumble_send_email
                            (
                                masterHandle    *master,
                                const char      *mailserver,
                                const char      *filename,
                                address         *sender,
                                address         *recipient
                            );
void                        rumble_debug(masterHandle *m, const char *svc, const char *msg, ...);
void                        rumble_vdebug(masterHandle *m, const char *svc, const char *msg, va_list args);
dvector                     *rumble_readconfig(const char *filename); // for modules
void                        comm_addEntry(rumbleService *svc, uint32_t bytes, char rejected);

//     Account and domain handling

uint32_t        rumble_domain_exists(const char *domain);           //! Checks if the domain is a local domain
uint32_t        rumble_account_exists_raw(const char *user, const char *domain);
rumble_domain   *rumble_domain_copy(const char *domain);
cvector         *rumble_domains_list(void);
uint32_t        rumble_account_exists(sessionHandle *session, const char *user, const char *domain);
rumble_mailbox  *rumble_account_data(uint32_t uid, const char *user, const char *domain);
rumble_mailbox  *rumble_account_data_auth(uint32_t uid, const char *user, const char *domain, const char *pass);
cvector         *rumble_database_accounts_list(const char *domain);
void            rumble_database_accounts_free(cvector *accounts);   //cleanup func for the function above.
void            rumble_domain_free(rumble_domain *domain);          //cleanup for domain copies.

//     Mailbox handling

rumble_parsed_letter    *rumble_mailman_readmail_private(FILE *fp, const char *boundary);
rumble_parsed_letter    *rumble_mailman_readmail(const char *filename);
void                    rumble_mailman_free_parsed_letter(rumble_parsed_letter *letter);

#   define merror() { \
        fprintf(stderr, "Memory allocation failed, this is bad!\n"); \
        rumble_debug(NULL, "core", "Memory allocation failed at %s, aborting!\n", rumble_mtime()); \
        exit(1); \
    }

// #define and     &&
// #define or      ||

//  -----------------------------------------------------------------------------------------------------------------------
//     Macro for implementing a dvector foreach() block as: For each A in B (as type T), using iterator I do {...}
//     example: int myValue, myArray[] = {1,2,3,4,5,6,7,8,9};
//     d_iterator iter;
//     foreach(int, myValue, myArray, iter) { printf("I got %d\n", myValue);
//     } - dforeach
//  -----------------------------------------------------------------------------------------------------------------------

extern masterHandle *Master_Handle;
extern dvector      *debugLog;
extern FILE         *sysLog;


void rumble_master_init_pop3(masterHandle *master);
void rumble_master_init_imap4(masterHandle *master);
void rumble_master_init_smtp(masterHandle *master);
void rumble_master_init_mailman(masterHandle *master);

extern mqueue * current_mail;


#endif //RUMBLE_H
