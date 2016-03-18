/* 
 * File:   main.c
 * Author: Nuke Sparrow <nukesparrow@bitmessage.ch>
 *
 * Created on February 12, 2016, 6:56 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <debuglogs.h>
#include <errorfc.h>

#include "socksserver.h"

static volatile int stopping = 0;

static void sig(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        stopping = 1;
        printf("Terminating\n");
    }
}

static int my_socks_server_peerfilter(void *closure, struct sockaddr * addr, socklen_t addr_len) {
    return 1;
}

/*
 * 
 */
int main(int argc, char** argv) {

    /* initialize signals */
    
    struct sigaction sa;
    sigset_t ss;

    WARN_IFM1(sigemptyset(&ss));
    sa.sa_handler = sig;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    WARN_IFM1(sigaction(SIGTERM, &sa, NULL));
    
    WARN_IFM1(sigemptyset(&ss));
    sa.sa_handler = sig;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    WARN_IFM1(sigaction(SIGINT, &sa, NULL));
    
    /* main loop */
    
    socks_server_t socks_server4, socks_server6;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(1080);

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(1080);
    
    set_debug_stream(stderr);
    
    int s4 = socks_server_start(&socks_server4, (struct sockaddr *)&sin, sizeof(sin));
    int s6 = socks_server_start(&socks_server6, (struct sockaddr *)&sin6, sizeof(sin6));
    
    if (s4) {
        socks_server4.peer_filter = my_socks_server_peerfilter;
    }
    if (s6) {
        socks_server6.peer_filter = my_socks_server_peerfilter;
    }

    if (s4 || s6) {
        printf("Socks server started\n");
        
        while (!stopping) {
            if (s4) {
                socks_server_periodic(&socks_server4, 10);
            }
            if (s6) {
                socks_server_periodic(&socks_server6, 10);
            }
        }
        
        if (s4)
            socks_server_cleanup(&socks_server4);
        if (s6)
            socks_server_cleanup(&socks_server6);
        
        printf("Socks server stopped\n");
    }
    
//    void* ptr = rcalloc(10);
//    rcincrease(ptr);
//
//    rcdecrease(ptr, NULL);
//    rcdecrease(ptr, NULL);

    return (EXIT_SUCCESS);
}

