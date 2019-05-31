#include "rumble.h"
#include "comm.h"

dvector *comm_mxLookup(const char *domain) {
    u_char  nsbuf[4096];
    memset(nsbuf, 0, sizeof(nsbuf));
    res_init(); // UNIX (IBM) MX resolver
    // Try to resolve domain
    int l = res_search(domain, ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));
    if (l < 0) return (NULL); // Resolving failed
    dvector *vec = dvector_init();
    ns_msg query_parse_msg;
    ns_rr query_parse_rr;
    ns_initparse(nsbuf, l, &query_parse_msg);
    for (int x = 0; x < ns_msg_count(query_parse_msg, ns_s_an); x++) {
        if (ns_parserr(&query_parse_msg, ns_s_an, x, &query_parse_rr)) {
            break;
        }

        if (ns_rr_type(query_parse_rr) == ns_t_mx) {
            mxRecord *mx = malloc(sizeof(mxRecord));
            if (!mx) merror();
            mx->host = (char*)calloc(1, 1024);
            if (!mx->host) merror();
            mx->preference = ns_get16((const unsigned char *) ns_rr_rdata(query_parse_rr));
            if (ns_name_uncompress(ns_msg_base(query_parse_msg),
                ns_msg_end(query_parse_msg),
                (const unsigned char *) ns_rr_rdata(query_parse_rr) + 2,
                (char*)mx->host, 1024) < 0) {
                    free((char*)mx->host);
                    free(mx);
                    continue;
            } else dvector_add(vec, mx);
        }
    }

    // Fall back to A record if no MX exists
    if (vec->size == 0) {
        struct hostent  *a = gethostbyname(domain);
        if (a) {
            struct in_addr x;
            mxRecord *mx = (mxRecord*)calloc(1, sizeof(mxRecord));
            if (!mx) merror();
            memcpy(&x, a->h_addr_list++, sizeof(x));
            char * b = inet_ntoa(x);
            mx->host = strclone(b);
            mx->preference = 10;
            free(a);
            dvector_add(vec, mx);
        }
    }
    return (vec);
}


void comm_mxFree(dvector *list) {
    d_iterator  iter;
    mxRecord    *mx;
    dforeach((mxRecord *), mx, list, iter) {
        free((char *) mx->host);
        free(mx);
    }
    dvector_destroy(list);
}
