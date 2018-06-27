//
// Created by Haris Mughees on 3/15/18.
//



#include "ClientServer.h"


int ClientServer::Client(std::string cmd, std::string args) {
    int srv_fd, cli_fd;
    sockaddr_un addr;
    proto_struct pb;
    status_struct st;


    strncpy(pb.command, cmd.data(), cmd.size());
    strncpy(pb.args, args.data(), args.size());

    std::cout << "sending: " << pb.command << std::endl;

    memset(&addr, 0, sizeof(addr));
    memset(&cmd, 0, sizeof(cmd));

    if ((srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    std::cout << "Client socket created" << std::endl;

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SRV_ADDR, sizeof(addr.sun_path) - 1);


    if (connect(srv_fd, (sockaddr *) &addr, sizeof(sockaddr_un)) < 0) {
        perror("Connection error, check server");
        exit(EXIT_FAILURE);

    }

    std::cout << "Client socket connected with server." << std::endl;

    if (write(srv_fd, &pb, sizeof(proto_struct)) < sizeof(proto_struct)) {
        perror("data not send properly");
        exit(EXIT_FAILURE);
    }

    std::cout << "Client data send.. I hope server is listening" << std::endl;

    if (read(srv_fd, &st, sizeof(status_struct)) != sizeof(status_struct)) {
        perror("data not read properly");
        exit(EXIT_FAILURE);
    }


    if (st.status) {
        printf("%s Done.\n", pb.command);
        if (st.data_size > 0) {
            auto *buff = new char[st.data_size];

            if (read(srv_fd, buff, st.data_size) != st.data_size) {
                perror("List data not read properly\n");
                exit(EXIT_FAILURE);
            } else {
                printf("------------------------------------------------------------\n");
                printf("%s", buff);
            }

        }
    } else {
        printf("%s", st.msg);
    }


    return 0;
}

int ClientServer::Server() {
    //this program makes unix domain server

    int srv_fd, cli_fd;
    sockaddr_un addr;
    pthread_t thread_id = 0;

    // creating socket

    if ((srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server socket created" << std::endl;

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SRV_ADDR, sizeof(addr.sun_path) - 1);//one less bytes to make sure 0 termination

    //check if socket file is already present then unlink it
    if (access(SRV_ADDR, F_OK) == 0) {
        unlink(SRV_ADDR);
    }


    if (::bind(srv_fd, (sockaddr *) &addr, sizeof(sockaddr_un)) == -1) {
        perror("bind error");
        exit(EXIT_FAILURE);

    }

    std::cout << "Server socket bind" << std::endl;

    if (listen(srv_fd, SRV_BACKLOG) < 0) {
        perror("listen error");
    }

    std::cout << "Server socket listening" << std::endl;

    BurnboxApi bb;// instance of burnbox

    thread_args th_buff; // argument structure for threds only
    th_buff.bb = &bb;
    th_buff.cli_fd = -1;

    while (1) {
        if ((th_buff.cli_fd = accept(srv_fd, NULL, NULL)) < 0) {
            perror("ERROR on accept.");
        } else {
            std::cout << "Server socket data accepted." << std::endl;
            pthread_create(&thread_id, 0, &Server_Func, (void *) &th_buff);//pointer
            pthread_detach(thread_id);
        }

    }


    return 1;
}

void *ClientServer::Server_Func(void *th_buff) {

    pthread_mutex_lock(&mutex1);// to make sure that no other thread can enter the lock

    status_struct cli_buff;// struct for client
    proto_struct srv_buff;// struct for server
    string err;

    //int *cli_fd = (int *) lp;

    auto *th_buff2 = (thread_args *) th_buff;


    std::cout << "Into thread" << std::endl;
    memset(&srv_buff, 0, sizeof(proto_struct));
    memset(&cli_buff, 0, sizeof(status_struct));
    int k;


    assert(k = read(th_buff2->cli_fd, &srv_buff, sizeof(proto_struct)) == sizeof(proto_struct));

    std::cout << "recieved command: " << srv_buff.command << std::endl;

    string list;
    list.clear();

    if (!strncmp(srv_buff.command, init_command, sizeof(init_command))) {

        cli_buff.status = th_buff2->bb->Init(err);
        strncpy(cli_buff.msg, err.data(), sizeof(cli_buff.msg));
        cli_buff.data_size = 0;


    } else if (!strncmp(srv_buff.command, add_command, sizeof(add_command))) {

        string filepath(srv_buff.args, sizeof(srv_buff.args));

        printf("path %s", filepath.data());
        //cli_buff.status = th_buff2->bb->AddFile(filepath, err);
        strncpy(cli_buff.msg, err.data(), sizeof(cli_buff.msg));
        cli_buff.data_size = 0;

    } else if (!strncmp(srv_buff.command, list_command, sizeof(list_command))) {

        cli_buff.status = th_buff2->bb->ListAllFiles(list, err);
        strncpy(cli_buff.msg, err.data(), sizeof(cli_buff.msg));
        cli_buff.data_size = list.size();

    }

    assert(write(th_buff2->cli_fd, &cli_buff, sizeof(status_struct)) == sizeof(status_struct));
    assert(write(th_buff2->cli_fd, list.data(), cli_buff.data_size) == cli_buff.data_size);

    pthread_mutex_unlock(&mutex1);
    return 0;
}



