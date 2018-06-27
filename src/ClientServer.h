//
// Created by Haris Mughees on 3/15/18.
//

#ifndef B2_CLIENTSERVER_H
#define B2_CLIENTSERVER_H

#include "BurnboxApi.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>
#include <assert.h>
#include <string>


namespace ClientServer {


#define SRV_ADDR "/tmp/srv_socket"
#define BUF_SIZE 1024
#define SRV_BACKLOG 1


    typedef struct {
        char command[50];
        char args[BUF_SIZE];
    } proto_struct;


    typedef struct {
        char msg[BUF_SIZE];
        bool status;
        size_t data_size;
    } status_struct;

    typedef struct {
        BurnboxApi *bb;
        int cli_fd;

    } thread_args;


     char init_command[] = "init";
     char add_command[] = "add";
     char delete_command[] = "delete";
     char recover_command[] = "recover";
     char list_command[] = "list";


     pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;


    int Client(std::string cmd, std::string args);

    int Server();

    void *Server_Func(void *lp);

    bool Server_CmdDecider();

    void process_program_options(const int argc, char **argv);

    bool Server_CmdDecider(const proto_struct &pb, status_struct &st);

};


#endif //B2_CLIENTSERVER_H
