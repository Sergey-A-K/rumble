#include "rumble.h"
#include "comm.h"
#include <stdarg.h>
#include <bits/types/struct_timeval.h>


#define COMM_LOG(x ...) rumble_debug(NULL, "comm", x);
#define COMM_TRACE(x ...) rumble_debug(NULL, "comm", x);


#define SOCKET_ERROR    - 1
#define TCP_NODELAY     0x200


void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return (&(((struct sockaddr_in *) sa)->sin_addr));
    }
    return (&(((struct sockaddr_in6 *) sa)->sin6_addr));
}


socketHandle comm_init(masterHandle *m, const char *port) {

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    // Force IPv4 or use default?
    hints.ai_family = rumble_config_int(m, "forceipv4") ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    struct addrinfo *servinfo, *p;

    const char * bindTo = 0;
    if (rumble_has_dictionary_value(m->_core.conf, "bindtoaddress"))
        bindTo = rumble_get_dictionary_value(m->_core.conf, "bindtoaddress");

    int rc = getaddrinfo(bindTo, port, &hints, &servinfo);
    if (rc) {
        rumble_debug(NULL, "comm", "ERROR: getaddrinfo: %s\n", gai_strerror(rc));
        return (0);
    }

    int sockfd;
    int yes = 1;
    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == SOCKET_ERROR) {
            rumble_debug(NULL, "comm", "ERROR: Couldn't create basic socket with protocol %#X!", p->ai_family);
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            rumble_debug(NULL, "comm", "ERROR: setsockopt failed!");
            exit(0);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            disconnect(sockfd);
            rumble_debug(NULL, "comm", "ERROR: Couldn't bind to socket (protocol %#X) on port %s!", p->ai_family, port);
            continue;
        }
        break;
    }

    if (p == NULL) { return (0); }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, 10) == SOCKET_ERROR) {
        rumble_debug(NULL, "comm", "ERROR: Couldn't listen on socket on port %s!", port);
        exit(0);
    }

    return (sockfd);
}


socketHandle comm_open(masterHandle *m, const char *host, unsigned short port) {

    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    // Force IPv4 or use default ?
    hints.ai_family = rumble_config_int(m, "forceipv4") ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    const char * bindTo = 0;
    if (rumble_has_dictionary_value(m->_core.conf, "outgoingbindtoaddress"))
        bindTo = rumble_get_dictionary_value(m->_core.conf, "outgoingbindtoaddress");
    char portc[10];
    sprintf(portc, "%u", port);
    int rc = getaddrinfo(bindTo, portc, &hints, &servinfo);
    if (rc != 0) {
        COMM_LOG("getaddrinfo: %s", gai_strerror(rc));
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return (0);
    }

    socketHandle sockfd = 0;
    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == SOCKET_ERROR) {
            perror("comm_open: server: socket");
            continue;
        }
        break;
    }

    int yes = 1;
    freeaddrinfo(servinfo); // all done with this structure
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &yes, sizeof(int));
    struct hostent * server = gethostbyname(host);
    struct sockaddr_in  x;
    x.sin_port = htons(port);
    x.sin_family = rumble_config_int(m, "forceipv4") ? AF_INET : AF_UNSPEC;
    x.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr *) *server->h_addr_list));
    if (server) {
        if (connect(sockfd, (struct sockaddr *) &x, sizeof x)) {
            return (0);
        }
    }

    return (sockfd);
}


ssize_t rumble_comm_printf(sessionHandle *session, const char *d, ...) {
    if (!d) return (0);
    va_list vl;
    va_start(vl, d);
    char   moo [1024];
    int len = vsnprintf(moo, 1024, d, vl) + 1;
    va_end(vl);
    char * buffer = (char *) calloc(1, len + 1);
    if (!buffer) merror();

    va_start(vl, d);
    vsprintf(buffer, d, vl);
    va_end(vl);

    int bufflen = strlen(buffer);

    if (send(session->client->socket, "", 0, 0) == -1) return (-1); /* Check if we can send at all (avoid GnuTLS crash) */
    if (session->client->tls_session != NULL) len = (session->client->tls_send) (session->client->tls_session, buffer, bufflen);
    else len = send(session->client->socket, buffer, bufflen, 0);
    session->client->bsent += bufflen;
    free(buffer);
    return (len);

}


void comm_accept(socketHandle sock, clientHandle *client) {
    socklen_t   sin_size = sizeof client->client_info;
    while (1) {
        // loop through accept() till we get something worth passing along
        client->socket = accept(sock, (struct sockaddr *) &(client->client_info), &sin_size);
        client->tls_session = 0;
        client->tls_send = 0;
        client->tls_recv = 0;
        client->brecv = 0;
        client->bsent = 0;
        client->rejected = 0;
        if (client->socket == SOCKET_ERROR) {
            perror("comm_accept: Error while attempting accept()");
            break;
        }

        FD_ZERO(&client->fd);
        FD_SET(client->socket, &client->fd);
        inet_ntop(client->client_info.ss_family,
                  get_in_addr((struct sockaddr *) &client->client_info),
                  client->addr, sizeof client->addr);
        break;
    }
}


char *rumble_comm_read(sessionHandle *session) {

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    char            b = 0;
    ssize_t         rc = 0;
    uint32_t        p;
    struct timeval  t;
    signed int      f;
    time_t          z;
    char            *ret = (char *) calloc(1, 1025);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if (!ret) {
        perror("Calloc failed!");
        exit(1);
    }

    t.tv_sec = (session->_tflags & RUMBLE_THREAD_IMAP) ? 30 : 10;
    t.tv_usec = 0;
    z = time(0);
    for (p = 0; p < 1024; p++) {
        f = select(session->client->socket + 1, &session->client->fd, NULL, NULL, &t);
        if (f > 0) {
            if (send(session->client->socket, "", 0, 0) == -1) return (NULL);
            if (session->client->tls_recv) rc = (session->client->tls_recv) (session->client->tls_session, &b, 1);
            else rc = recv(session->client->socket, &b, 1, 0);
            if (rc <= 0) {
                free(ret);
                return (NULL);
            }

            /*
             * printf("%c\n", b);
             */
            ret[p] = b;
            if (b == '\n') break;
        } else {
            z = time(0) - z;
            free(ret);
            printf("timeout after %"PRIdPTR " secs! %d\r\n", z, f);
            return (NULL);
        }
    }

    if (session->_svc) ((rumbleService *) session->_svc)->traffic.received += strlen(ret);
    session->client->brecv += strlen(ret);
    return (ret);
}




char *rumble_comm_read_bytes(sessionHandle *session, int len) {

    /*~~~~~~~~~~~~~~~~~~~~*/
    char            *buffer;
    ssize_t         rc = 0;
    struct timeval  t;
    signed int      f;
    /*~~~~~~~~~~~~~~~~~~~~*/

    t.tv_sec = (session->_tflags & RUMBLE_THREAD_IMAP) ? 1000 : 10;
    t.tv_usec = 0;
    buffer = (char *) calloc(1, len + 1);
    f = select(session->client->socket + 1, &session->client->fd, NULL, NULL, &t);
    if (f > 0) {
        if (session->client->tls_recv) rc = (session->client->tls_recv) (session->client->tls_session, buffer, len);
        else rc = recv(session->client->socket, buffer, len, 0);
        if (rc <= 0) {
            free(buffer);
            return (NULL);
        }

        if (session->_svc) ((rumbleService *) session->_svc)->traffic.received += len;
        session->client->brecv += len;
        return (buffer);
    }

    return (0);
}

ssize_t rumble_comm_send(sessionHandle *session, const char *message) {
    if (session->_svc) ((rumbleService *) session->_svc)->traffic.sent += strlen(message);
    session->client->bsent += strlen(message);
    if (session->client->tls_send) { // Check if we can send at all (avoid GnuTLS crash)
        return ((session->client->tls_send) (session->client->tls_session, message, strlen(message)));
    } else {
        if (send(session->client->socket, "", 0, 0) == -1) {
            return (-1);
        } else {
            return (send(session->client->socket, message, strlen(message), 0));
        }
    }
}

ssize_t rumble_comm_send_bytes(sessionHandle *session, const char *message, size_t len) {
    if (session->_svc) ((rumbleService *) session->_svc)->traffic.sent += len;
    session->client->bsent += len;
    if (session->client->tls_send) { // Check if we can send at all (avoid GnuTLS crash)
        return ((session->client->tls_send) (session->client->tls_session, message, len));
    } else {
        return (send(session->client->socket, message, len, 0));
    }
}
