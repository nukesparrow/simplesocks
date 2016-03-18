
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#ifdef STATIC_ANL
#include <anl.h>
#endif

#include <debuglogs.h>
#include <errorfc.h>
#include <bufs.h>

#include "socksserver.h"

static ssize_t send_nosignal(int fd, const void *buf, size_t n) {
    ssize_t tw = 0;
    
    while (n > 0) {
        ssize_t nw = send(fd, buf, n, MSG_NOSIGNAL);
        
        if (nw <= 0) {
            return nw == -1 && tw == 0 ? (ssize_t)-1 : tw;
        }
        
        tw += nw;
        buf += nw;
        n -= nw;
    }
    
    return tw;
}

#define DEF_SOCKET_READ_TIMEOUT 300

#define PROXYPROTO_HTTP 1
#define PROXYPROTO_CONNECT 2
#define PROXYPROTO_SOCKS4 4
#define PROXYPROTO_SOCKS5 5

struct resolverstate;
typedef struct resolverstate resolverstate_t;

struct socks_server_connection {
    int s, ts;
    
    time_t s_last, ts_last;
    
    int ts_connecting;
    
    struct sockaddr * addr;
    socklen_t addr_len;
    
    unsigned char resolve_hostname[256];
    uint16_t resolve_port;
    
    struct sockaddr_storage connect_addr;
    socklen_t connect_addr_len;
    
    int stage;
    buf_t s_buf;
    
    int protocol;

    struct gaicb resolve_gaicb;
    struct gaicb* resolve_gaicb_ptr;

    socks_server_connection_t* next;
};

struct resolverstate {
    struct socks_server_connection* conn_ptr;
};

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MAX_UPDATE(a,b) if((b)>(a)) { a = (b); }

int socks_server_start(socks_server_t * s, struct sockaddr * addr, socklen_t addr_len) {
    if (addr == NULL) {
        return 0;
    }

    memset(s, 0, sizeof(socks_server_t));
    s->s = -1;
    
    s->socket_read_timeout = DEF_SOCKET_READ_TIMEOUT;
    
    WARNFAIL_IFM1(s->s = socket(addr->sa_family, SOCK_STREAM, 0));
    
    if (addr->sa_family == AF_INET6) {
        int val = 1;
        WARNFAIL_IFNZ(setsockopt(s->s, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)));
    }
    WARNFAIL_IFNZ(bind(s->s, addr, addr_len));
    WARNFAIL_IFNZ(listen(s->s, 64));
    
    return 1;
    
    CATCH;
    
    if (s->s != -1) {
        WARN_IFM1(close(s->s));
    }
    
    return 0;
}

static int clients_connected = 0;

#define dumpcc() { debugf("Clients connected: %d\n", clients_connected); }

static void handle_new_socket(socks_server_t * s, int sock, struct sockaddr * addr, socklen_t addr_len) {
    if (s->peer_filter != NULL && !s->peer_filter(s->peer_filter_closure, addr, addr_len)) {
        WARN_IFM1(send_nosignal(sock, "\x05\xff", 2));
        WARN_IFM1(close(sock));
        return;
    }
    
    socks_server_connection_t* conn = calloc(1, sizeof(socks_server_connection_t));
    
    buf_initialize(&conn->s_buf);
    
    conn->next = s->cc;
    s->cc = conn;
    
    conn->s = sock;
    conn->ts = -1;
    
    conn->s_last = time(NULL);
    
    conn->addr = addr;
    conn->addr_len = addr_len;
    
    clients_connected++;
    dumpcc();
}

static int send_data(int sock, uint8_t* buf, size_t len) {
    uint8_t* buf_ptr = buf;
    size_t remainder = len;

    while (remainder > 0) {
        int nw;
        WARN_IFM1(nw = send_nosignal(sock, buf_ptr, remainder));

        if (nw <= 0) {
            return 0;
        }

        buf_ptr += nw;
        remainder -= nw;
    }
    
    return 1;
}

static int forward_data(int sfrom, int sto) {
    uint8_t buf[2048];

    int nr = recv(sfrom, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
    
    WARN_IFM1(nr);
    
    if (nr <= 0) {
        return 0;
    }
    
    return send_data(sto, buf, nr);
}

static int buffer_data(int sock, buf_t* buffer) {
    uint8_t buf[2048];

    int nr = recv(sock, buf, sizeof(buf), MSG_DONTWAIT | MSG_NOSIGNAL);
    
    WARN_IFM1(nr);
    
    if (nr <= 0) {
        return 0;
    }
    
    return buf_append(buffer, buf, nr);
}

static int flush_buffer(int sock, buf_t* buffer) {
    if (buffer->size == 0) {
        return 1;
    }
    
    uint8_t* ptr = buffer->data;
    size_t rem = buffer->size;
    
    while (rem >= 0) {
        int nw = send_nosignal(sock, ptr, rem);
        
        WARN_IFM1(nw);
    
        if (nw < 0) {
            buf_shift(NULL, buffer, buffer->size - rem);
            return 0;
        }
        
        ptr += nw;
        rem -= nw;
    }
    
    buf_free(buffer);
    buf_initialize(buffer);
    
    return 1;
}

#define CONNSTAGE_ECHO -2
#define CONNSTAGE_FAIL -1
#define CONNSTAGE_INIT 0
#define CONNSTAGE_CONNECTED 1
#define CONNSTAGE_SOCK5SRECVCMD 52
#define CONNSTAGE_SOCK5RESOLUTION 53
#define CONNSTAGE_SOCK5RESOLUTION_INPROGRESS 54
#define CONNSTAGE_SOCK5RESOLUTIONFAIL -53
#define CONNSTAGE_SOCK5CONNECT 55
#define CONNSTAGE_SOCK5CONNECTING 56
#define CONNSTAGE_SOCK5CONNECTED 57
#define CONNSTAGE_SOCK5CONNECTFAIL -52

static void setconnectaddr(socks_server_connection_t * conn, struct addrinfo* result) {
    struct sockaddr_in* addr4 = NULL;
    struct sockaddr_in6* addr6 = NULL;

    if (result->ai_family == AF_INET) {
        conn->connect_addr.ss_family = AF_INET;
        conn->connect_addr_len = sizeof(struct sockaddr_in);

        addr4 = (struct sockaddr_in *)&conn->connect_addr;
        memcpy(&conn->connect_addr, result->ai_addr, result->ai_addrlen);
        addr4->sin_port = htons(conn->resolve_port);
    } else if (result->ai_family == AF_INET6) {
        conn->connect_addr.ss_family = AF_INET6;
        conn->connect_addr_len = sizeof(struct sockaddr_in6);

        addr6 = (struct sockaddr_in6*)&conn->connect_addr;
        memcpy(&conn->connect_addr, result->ai_addr, result->ai_addrlen);
        addr6->sin6_port = htons(conn->resolve_port);
    } else {
        fprintf(stderr, "result->ai_family bad: %d\n", result->ai_family);
        //conn->stage = CONNSTAGE_FAIL; // FIXME : unused value
        abort();
    }
}

static void resolve_addr_complete_ifready(socks_server_connection_t * conn) {
    int r = gai_error(&conn->resolve_gaicb);
    
    if (r == EAI_INPROGRESS) {
        return;
    }
    
    if (r == 0 || r == EAI_ALLDONE) {
        setconnectaddr(conn, conn->resolve_gaicb.ar_result);

        freeaddrinfo(conn->resolve_gaicb.ar_result);
        conn->resolve_gaicb_ptr = NULL;

        conn->stage = CONNSTAGE_SOCK5CONNECT;
        
        return;
    }
    
    if (r == EAI_SYSTEM) {
        perror("gai_error");
    } else {
        fprintf(stderr, "gai_error: %s\n", gai_strerror(r));
    }
    
    if (conn->resolve_gaicb.ar_result != NULL) {
        freeaddrinfo(conn->resolve_gaicb.ar_result);
        conn->resolve_gaicb.ar_result = NULL;
    }
    conn->stage = CONNSTAGE_FAIL;
}

static void resolve_addr_cancel(socks_server_connection_t * conn) {
    if (conn->stage != CONNSTAGE_SOCK5RESOLUTION_INPROGRESS) {
        return;
    }
    
    gai_cancel(&conn->resolve_gaicb);
    
    if (conn->resolve_gaicb.ar_result != NULL) {
        freeaddrinfo(conn->resolve_gaicb.ar_result);
    }
}

static void resolve_addr_start(socks_server_connection_t * conn) {
    // (char *)conn->resolve_hostname, NULL, NULL, &result
    
    memset(&conn->resolve_gaicb, 0, sizeof(conn->resolve_gaicb));

    conn->resolve_gaicb.ar_name = (char *)conn->resolve_hostname;
    conn->resolve_gaicb.ar_service = NULL;
    conn->resolve_gaicb.ar_request = NULL;
    
    conn->resolve_gaicb_ptr = &conn->resolve_gaicb;

    int r;
    
    conn->stage = CONNSTAGE_SOCK5RESOLUTION_INPROGRESS;

    if ((r = getaddrinfo_a(GAI_NOWAIT, &conn->resolve_gaicb_ptr, 1, NULL)) != 0) {
        if (r == EAI_ALLDONE) {
            resolve_addr_complete_ifready(conn);
            return;
        }
        
        goto fail;
    }
 
    return;
    
    fail:
    conn->stage = CONNSTAGE_SOCK5RESOLUTIONFAIL;
}

static void connect_addr(socks_server_connection_t * conn) {
    WARNFAIL_IFM1(conn->ts = socket(conn->connect_addr.ss_family, SOCK_STREAM, 0));
    
    int fl;
    WARNFAIL_IFM1(fl = fcntl(conn->ts, F_GETFL, 0));
    WARNFAIL_IFM1(fcntl(conn->ts, F_SETFL, fl | O_NONBLOCK));
    
    if (connect(conn->ts, (struct sockaddr *)&conn->connect_addr, conn->connect_addr_len) == -1) {
        if (errno != EINPROGRESS) {
            perror("connect");
            goto fail;
        }
    }
    
    conn->stage = CONNSTAGE_SOCK5CONNECTING;
    conn->ts_last = time(NULL);
    
    debugf("Connecting\n");

    return;
    
    CATCH;
    
    debugf("Connection failed\n");
    
    if (conn->ts != -1) {
        WARN_IFM1(close(conn->ts));
        conn->ts = -1;
    }
    
    conn->stage = CONNSTAGE_SOCK5CONNECTFAIL;
}

static int handle_received_data(socks_server_connection_t * conn, int from_client, int from_tunnel) {

    if (from_tunnel) {
        conn->ts_last = time(NULL);

        if (!forward_data(conn->ts, conn->s)) {
            return 0;
        }
    }
    
    if (from_client) {
        conn->s_last = time(NULL);

        if (conn->ts != -1) {
            if (!forward_data(conn->s, conn->ts)) {
                return 0;
            }
        } else {
            if (!buffer_data(conn->s, &conn->s_buf)) {
                return 0;
            }
            if (!buf_terminatezero(&conn->s_buf)) {
                debugf("z fail\n");
                return 0;
            }

            if (conn->stage == CONNSTAGE_INIT) {
                
                if (buf_length(&conn->s_buf) == 0) {
                    return 1;
                }
                
                if (conn->protocol == 0) {
                    if (conn->s_buf.data[0] == 4) {
                        debugf("SOCKS4 not supported");
                        return 0; // socks 4 not supported
                    } else if (conn->s_buf.data[0] == 5) {
                        conn->protocol = PROXYPROTO_SOCKS5;
                    } else {
                        debugf("unsupported protocol %d\n", conn->s_buf.data[0]);
                        return 0;
                    }
                }
                
                // socks5 only here
                int n_methods = conn->s_buf.data[1];
                size_t ofs = 2 + n_methods;
                
                if (!buf_shift(NULL, &conn->s_buf, ofs)) {
                    return 1; // not enough input data, receive more data
                }
                
                send_data(conn->s, (uint8_t*)"\x05\x00", 2); // TODO : auth support
                
                conn->stage = CONNSTAGE_SOCK5SRECVCMD;
                
            }
            
            if (conn->stage == CONNSTAGE_SOCK5SRECVCMD && conn->s_buf.size >= 10) { // socks5 / Once the method-dependent subnegotiation has completed
                uint8_t* b = conn->s_buf.data;
                
                if (*b != 5) {
                    debugf("Bad socks version: %d\n", *b);
                    return 0;
                }
                b++;
                
                if (*b != 1) {
                    debugf("Unsupported command: %d\n", *b);
                    return 0;
                }
                b++;
                
                if (*b != 0) {
                    debugf("Bad reserved field value: %d\n", *b);
                    return 0;
                }
                b++;
                
                int atyp = *b;
                b++;
                
                struct sockaddr_in* addr4 = NULL;
                struct sockaddr_in6* addr6 = NULL;
                
                debugf("atyp=%d\n", atyp);

                if (atyp == 1 || atyp == 4) { // IPv4 / IPv6 addresses
                    uint8_t packet[22];
                    uint8_t* ptr;
                    if (!buf_shift_mem((void*)packet, &conn->s_buf, atyp == 1 ? 10 : 22)) {
                        return 1; // more data required
                    }
                    ptr = packet + 4;
                    
                    if (atyp == 1) {
                        conn->connect_addr.ss_family = AF_INET;
                        conn->connect_addr_len = sizeof(struct sockaddr_in);
                        
                        addr4 = (struct sockaddr_in*)&conn->connect_addr;

                        memcpy(&addr4->sin_addr, ptr, 4); ptr+=4;
                        memcpy(&addr4->sin_port, ptr, 2);
                    } else {
                        conn->connect_addr.ss_family = AF_INET6;
                        conn->connect_addr_len = sizeof(struct sockaddr_in6);

                        addr6 = (struct sockaddr_in6*)&conn->connect_addr;

                        memcpy(&addr6->sin6_addr, ptr, 16); ptr+=16;
                        memcpy(&addr6->sin6_port, ptr, 2);
                    }
                    
                    conn->stage = CONNSTAGE_SOCK5CONNECT;
                    
                } else if (atyp == 3) { // Domain name
                    uint8_t packet[7+256];
                    uint8_t* ptr;
                    if (!buf_shift_mem((void*)packet, &conn->s_buf, (7 + *b))) {
                        return 1; // more data required
                    }
                    ptr = packet + 4;

                    size_t len = (uint8_t)*ptr;
                    ptr++;

                    char hostname[256];
                    memcpy(hostname, ptr, len);
                    hostname[len] = 0;
                    ptr+=len;
                    
                    uint16_t port;
                    memcpy(&port, ptr, 2); ptr+=2;
                    
                    strcpy((char*)conn->resolve_hostname, hostname);
                    conn->resolve_port = ntohs(port);

                    conn->stage = CONNSTAGE_SOCK5RESOLUTION;
                } else {
                    debugf("Bad address type: %d\n", *b);
                    send_nosignal(conn->s, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
                    return 0;
                }
            }
            
            if (conn->stage == CONNSTAGE_SOCK5RESOLUTION) {
                resolve_addr_start(conn);
            }

            if (conn->stage == CONNSTAGE_SOCK5RESOLUTIONFAIL) {
                debugf("Resolution failed\n");
                send_nosignal(conn->s, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
                return 0;
            }

            if (conn->stage == CONNSTAGE_SOCK5CONNECTFAIL) {
                debugf("Connection failed\n");
                send_nosignal(conn->s, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
                return 0;
            }

            if (conn->stage == CONNSTAGE_FAIL) {
                return 0;
            }

            if (conn->stage == CONNSTAGE_ECHO) {
                if (!forward_data(conn->s, conn->s)) {
                    return 0;
                }
            }

        }
    }
    
    return 1;
}

static int handle_write_ready(socks_server_connection_t * conn) {
    debugf("Connected\n");
    
    int fl;
    WARNFAIL_IFM1(fl = fcntl(conn->ts, F_GETFL, 0));
    WARNFAIL_IFM1(fcntl(conn->ts, F_SETFL, fl & ~O_NONBLOCK));

    if (send_nosignal(conn->s, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10) != 10) {
        debugf("write failed\n");
        return 0;
    }
    if (!flush_buffer(conn->ts, &conn->s_buf)) {
        debugf("buffer flushing failed\n");
        return 0;
    }

    conn->stage = CONNSTAGE_CONNECTED;
    conn->ts_last = time(NULL);
    
    return 1;
    
    CATCH;
    
    return 0;
}

#define handle_except(x) (0)
//static int handle_except(socks_server_connection_t * conn) {
//    return 0;
//}

void socks_server_periodic_select_prepare(socks_server_t * s, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, int* maxfd) {
    FD_SET(s->s, readfds);
    MAX_UPDATE(*maxfd, s->s);

    socks_server_connection_t* cc = s->cc;

    while (cc != NULL) {
        if (cc->stage == CONNSTAGE_SOCK5RESOLUTION_INPROGRESS) {
            resolve_addr_complete_ifready(cc);
        }
        
        if (cc->stage == CONNSTAGE_SOCK5RESOLUTION_INPROGRESS) {
            // skip
        } else if (cc->stage == CONNSTAGE_SOCK5CONNECTING && cc->ts != -1) {
            FD_SET(cc->ts, writefds);
            FD_SET(cc->ts, exceptfds);
            MAX_UPDATE(*maxfd, cc->ts);
        } else {
            FD_SET(cc->s, readfds);
            MAX_UPDATE(*maxfd, cc->s);
            if (cc->ts != -1) {
                FD_SET(cc->ts, readfds);
                MAX_UPDATE(*maxfd, cc->ts);
            }
        }

        cc = cc->next;
    }
}

static void client_conn_cleanup(socks_server_connection_t * conn) {
    if (conn->s != -1) {
        WARN_IFM1(close(conn->s));
    }
    
    if (conn->ts != -1) {
        WARN_IFM1(close(conn->ts));
    }
    
    buf_free(&conn->s_buf);
    
    resolve_addr_cancel(conn);

    if (conn->resolve_gaicb.ar_result != NULL) {
        freeaddrinfo(conn->resolve_gaicb.ar_result);
        conn->resolve_gaicb.ar_result = NULL;
    }
    
    free(conn);
    
    clients_connected--;
    dumpcc();
}

int socks_server_periodic_process(socks_server_t * s, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, int* num) {
    if (*num > 0) {
        if (FD_ISSET(s->s, readfds)) {
            int sock;
            struct sockaddr_storage * sin;
            socklen_t sin_len = sizeof(struct sockaddr_storage);
            WARNFAIL_IFM1(sock = accept(s->s, (struct sockaddr *)&sin, &sin_len));
            handle_new_socket(s, sock, (struct sockaddr *)&sin, sin_len);
            (*num)--;
        }
    }

    socks_server_connection_t* cc = s->cc;
    socks_server_connection_t* cc_prev = NULL;

    while (cc != NULL) {
        int delete = 0;

        if (*num > 0) {
            int tunnel_event = 0;
            if (cc->stage == CONNSTAGE_SOCK5CONNECTING && cc->ts != -1) {
                if (FD_ISSET(cc->ts, exceptfds)) {
                    tunnel_event = 1;
                    if (!handle_except(cc)) {
                        delete = 1;
                    }
                } else if (FD_ISSET(cc->ts, writefds)) {
                    tunnel_event = 1;
                    if (!handle_write_ready(cc)) {
                        delete = 1;
                    }
                }
            }

            int data_from_client = FD_ISSET(cc->s, readfds);
            int data_from_tunnel = cc->ts != -1 ? FD_ISSET(cc->ts, readfds) : 0;

            if ((data_from_client || data_from_tunnel) && !delete) {
                if (!handle_received_data(cc, data_from_client, data_from_tunnel)) {
                    debugf("Connection data handle fail, stage: %d\n", cc->stage);
                    delete = 1;
                }
            }

            if (data_from_client) {
                (*num)--;
            }
            if (data_from_tunnel || tunnel_event) {
                (*num)--;
            }
        }
        
        if (cc->stage == CONNSTAGE_SOCK5CONNECT) {
            connect_addr(cc);
        }

        if (!delete) {
            time_t th = time(NULL) - s->socket_read_timeout;
            
            if (cc->s_last < th) {
                debugf("Connection timed out\n");
                delete = 1;
            }

            if (cc->ts != -1 && cc->ts_last < th) {
                debugf("Connection timed out\n");
                delete = 1;
            }
        }

        if (delete) {
            if (cc_prev) {
                cc = cc->next;

                client_conn_cleanup(cc_prev->next);
                cc_prev->next = cc;
            } else {
                socks_server_connection_t* cc_del = cc;
                s->cc = cc->next;

                client_conn_cleanup(cc_del);
                
                cc = s->cc;
            }
        } else {
            cc_prev = cc;
            cc = cc->next;
        }
    }
    
    return 1;
    
    CATCH;
    
    return 0;
}

int socks_server_periodic(socks_server_t * s, int wait_millis) {
    struct timeval tv;
    tv.tv_sec = wait_millis / 1000;
    tv.tv_usec = (wait_millis - (tv.tv_sec * 1000)) * 1000;

    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    int maxfd = -1;
    
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

    socks_server_periodic_select_prepare(s, &readfds, &writefds, &exceptfds, &maxfd);
    
    int num;

    if (maxfd != -1) {
        WARNFAIL_IFM1(num = select(maxfd + 1, &readfds, &writefds, &exceptfds, &tv));
    } else {
        WARN_IFM1(usleep(wait_millis * 1000));
    }
    
    return socks_server_periodic_process(s, &readfds, &writefds, &exceptfds, &num);

    CATCH;

    return 0;
}

void socks_server_cleanup(socks_server_t * s) {
    WARNFAIL_IFNZ(close(s->s));
    s->s = -1;
    
    while (s->cc != NULL) {
        socks_server_connection_t* c = s->cc;
        
        s->cc = c->next;

        client_conn_cleanup(c);
    }
    
    return;
    CATCH;
}
