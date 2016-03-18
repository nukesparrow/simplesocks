/* 
 * File:   socksserver.h
 * Author: Nuke Sparrow <nukesparrow@bitmessage.ch>
 *
 * Created on February 12, 2016, 6:56 PM
 */

#ifndef SOCKSSERVER_H
#define	SOCKSSERVER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>

typedef int socks_server_peerfilter(void *closure, struct sockaddr * addr, socklen_t addr_len);

struct socks_server_connection;
typedef struct socks_server_connection socks_server_connection_t;

typedef struct {
    /**
     * server socket connections
     */
    int s;

    /**
     * client connections linked list
     */
    socks_server_connection_t* cc;
    
    time_t socket_read_timeout;

    socks_server_peerfilter* peer_filter;
    void* peer_filter_closure;
} socks_server_t;

int socks_server_start(socks_server_t * s, struct sockaddr * addr, socklen_t addr_len);
int socks_server_periodic(socks_server_t * server, int wait_millis);
void socks_server_periodic_select_prepare(socks_server_t * s, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, int* maxfd);
int socks_server_periodic_process(socks_server_t * s, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, int* num);
void socks_server_cleanup(socks_server_t * server);

#define socks_server_setpeerfilter(s, f, c) { (s)->peer_filter = (f); (s)->peer_filter_closure = (c); }

#ifdef	__cplusplus
}
#endif

#endif	/* SOCKSSERVER_H */

