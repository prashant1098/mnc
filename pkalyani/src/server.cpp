#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <bits/stdc++.h>
#include <vector>
#include <cstring>
using namespace std;
#include "../include/global.h"
#include "../include/logger.h"
fd_set current_socket, ready_socket;
int clientNo;
struct client{
	int socketId;
	int no;
	string hostName;
	string ipAddr;
	int portNo;
	string blockedList[10];
	int blockedNum;
    int loginStatus;
    int sendMsgNum;
    int recvMsgNum;
    string msgBuffer[100];
	int bufferMsg;
}clients[5];


int createServer(int PORT)
{
    int server_fd, new_socket, valread, maxIndex, fdaccept = 0;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = { 0 };
    socklen_t caddr_len;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        // cout<<"Error server_fd";
        exit(0);
    }
    
    if(server_fd == 0)
    {
        // cout<<"Error server_fd";
        exit(0);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        close(server_fd);
        // cout<<"Error bind";
        exit(0);
    }

    if (listen(server_fd, 5) < 0) {
        // cout<<"Error";
    }

    FD_ZERO(&current_socket);
    FD_ZERO(&ready_socket);
    
   
    FD_SET(server_fd, &current_socket);
    FD_SET(0, &current_socket);

    maxIndex = server_fd;
    string ipAddr;
    ipAddr = getIp();
    // cout<<"\n server ip is:"<<ipAddr;
    while (true)
    {
        memcpy(&ready_socket, &current_socket, sizeof(current_socket));
        int selectReturn = select(maxIndex + 1, &ready_socket, NULL, NULL, NULL);
        if(selectReturn<0){
            // perror("Failure Select!!");
        }
        if(selectReturn>0){
            int i = 0;
            string command;
            while(i<=maxIndex){
                if(FD_ISSET(i,&ready_socket)){
                    if(i==0){
                        getline(std::cin,command,'\n');
                        // cout<<"\nSever got command:"<<command;
                         if((command.compare("AUTHOR"))==0){
                            authorCommand(command);
                        }
                         else if((command.compare("IP"))==0){
                            ipCommand(ipAddr,command);
                         }
                         else if((command.compare("PORT"))==0){
                            portCommand(server_fd,command,PORT);
                         }
                         else if((command.compare("EXIT"))==0){
                            close(server_fd);
							exit(0);
                         }
                         else if((command.compare("LIST"))==0){
                            listCommand(command);
                         }
                    

                    }
                    else if(i==server_fd){
                        // printf("\nAccepting connection");
                        string buffer;
                        struct sockaddr_in client_addr;
                        caddr_len = sizeof(client_addr);
                        fdaccept = accept(server_fd, (struct sockaddr *)&client_addr, &caddr_len);
                         if(fdaccept < 0){
                                 printf("\nAccept failed");
                         }
                        FD_SET(fdaccept, &current_socket);
                        clientNo = addToClients(fdaccept, client_addr, clientNo, 0);
                        if(fdaccept > maxIndex) maxIndex = fdaccept;
                    } 
                    else{
                        // cout<<"\nReceiving command from client";
                        char *buffer = (char*) malloc(sizeof(char)*1024);
                        memset(buffer, '\0', 1024);
                        if(recv(i, buffer, 1024, 0) <= 0){
                                close(i);
                                // printf("\nRemote Host terminated connection!\n");
                                clientNo--;
                                FD_CLR(i, &current_socket);
                        }
                        else {
                                
                                char *cmd = buffer;
                                // printf("\nClient sent me: %s\n", cmd);
                                processCmdFromClient(string(cmd), i);	                        	
                                fflush(stdout);
                        }
                        free(buffer);
                    }
                }
                i+=1;
            }
        }
    }
    
    return 0;
}

int processCmdFromClient(string command, int sockIndex){

	string clientIp;
    int structIndex, i= 0;
    // cout<<"\nsocket index:"<<sockIndex;
    while(i<clientNo){
        if(sockIndex==clients[i].socketId){
            clientIp = clients[i].ipAddr;
            structIndex = i;
            break;
        }
        i+=1;
    }
    // cout<<"\nstruct index:"<<structIndex;
    vector <string> tokens;
    stringstream check1(command);
    string intermediate;
    while(getline(check1, intermediate, ' '))
    {
        tokens.push_back(intermediate);
    }
    // cout<<"\n The command from client is:"<<tokens[0];
    if((tokens[0].compare("LOGOUT"))==0){
        clients[structIndex].loginStatus = 0;
        close(sockIndex);
        FD_CLR(sockIndex,&current_socket);
    }
    else if((tokens[0].compare("REFRESH"))==0){
        sortList();
        sendLoginUserList(sockIndex,"REFRESH");
    }
    else if((tokens[0].compare("PORT_SEND"))==0){
        // cout<<"\n Inside port send";
        clients[structIndex].portNo = std::stoi(tokens[1]);
        clients[structIndex].loginStatus=1;
        // cout<<"\nclient port number"<<clients[structIndex].portNo;
        sortList();
        sendLoginUserList(sockIndex,"CLIST");
    }
    else if((tokens[0].compare("BLOCKIP"))==0){
        int i =0;
        while(i<clientNo){
            if (clients[i].socketId == sockIndex){
                clients[i].blockedList[clients[i].blockedNum] = tokens[1];
                clients[i].blockedNum+=1;
                break;
            }
            i+=1;
        }
    }
    else if((tokens[0].compare("UNBLOCKIP"))==0){
        int i =0;
        while(i<clientNo){
            if (clients[i].socketId == sockIndex){
                int j= 0;
                while(j<clients[i].blockedNum){
                    if(clients[i].blockedList[j]==tokens[1]){
                        clients[i].blockedList[j].clear();
                    }
                    j+=1;
                }
            }
            }
            i+=1;
        }
    
    return 0;
   
}

void sendLoginUserList(int sockIndex, string command){
    // cout<<"\nInside send login user list";
    string clientMessage;
    char message[1024];
    int i =0;
    clientMessage = command + " ";
    while(i<clientNo){
        if(clients[i].loginStatus>0){
            clientMessage =  clientMessage + "no:" + std::to_string(clients[i].no);
            clientMessage+=",";
            clientMessage =  clientMessage + "hostname:" + clients[i].hostName;
            clientMessage+=",";
            clientMessage =  clientMessage + "ip:" + clients[i].ipAddr;
            clientMessage+=",";
            clientMessage =  clientMessage + "port:" + to_string(clients[i].portNo);
            clientMessage+=" ";
        }
        i+=1;
    }
    // cout<<"\nMessage for client:"<<clientMessage;
    strcpy(message, clientMessage.c_str());
    int check = send(sockIndex, message, sizeof(message), 0);
    if(check>0){
        // cout<<"\nDone "<<command;
    }
    fflush(stdout);
}
	
void sortList(){
    // cout<<"\nInside sort list";
    struct client temp;
    int i = 1;
    int j, port;
    while(i<clientNo){
        temp = clients[i];
        j = i -1;
        while(j>=0 && clients[j].portNo>temp.portNo){
            clients[j+1] = clients[j];
            clients[j+1].no = j+2;
            j-=1;
        }
        clients[j+1]=temp;
        clients[j+1].no = j+2;
        i+=1;
    }
}


int listCommand(string command){
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
    for (int i = 0; i < clientNo; i++){

        if(clients[i].loginStatus == 1){

            cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",clients[i].no,clients[i].hostName.c_str(),clients[i].ipAddr.c_str(),clients[i].portNo);

        }
    }
    cse4589_print_and_log("[%s:END]\n", command.c_str());  
    return 0;
}

int authorCommand(string command){
    char ubName[10] = "pkalyani";
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str()); 
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", ubName);
	cse4589_print_and_log("[%s:END]\n", command.c_str());
    return 0;
}

int ipCommand(string ip, string command){

	cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
	cse4589_print_and_log("IP:%s\n", ip.c_str());
	cse4589_print_and_log("[%s:END]\n", command.c_str());

	return 0;
}

int portCommand(int socket, string command, int port){
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
	cse4589_print_and_log("PORT:%d\n", port);
	cse4589_print_and_log("[%s:END]\n", command.c_str());
    return 0;
}

std::string getIp(){
    char* dnsServer = "8.8.8.8";
    int dnsPort = 53;

    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        // std::cout << "Socket error" << std::endl;
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dnsServer);
    serv.sin_port = htons(dnsPort);

    int error = connect(sock, (const struct sockaddr*)&serv, sizeof(serv));
    if (error < 0)
    {
        // cout<<"\nError no:"<<errno;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    int err = getsockname(sock, (struct sockaddr*)&name, &namelen);

    char buffer[80];
    const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 80);
    if(p != NULL)
    {
        return(std::string(buffer));
    }
    else
    {
        // cout << "\nError number: " << errno;
    }

    close(sock);
    return "";
}

int addToClients(int fdaccept, struct sockaddr_in client_addr, int j, int client_port){
	// cout<<"\nInside client";
    int i = 0;
    char *ip_addr;
    ip_addr = inet_ntoa(client_addr.sin_addr);
    // while(i<clientNo){
    //     if(clients[i].ipAddr.compare(std::string(ip_addr))==0 && clients[i].portNo==client_port){
    //         return j;
    //     }
    // }

	char host[1024];
	char service[20];
	clients[j].socketId = fdaccept;
	clients[j].no = j + 1;
	getnameinfo((struct sockaddr *) &client_addr, sizeof client_addr, host, sizeof host, service, sizeof service, 0);
    // cout<<"\nhost:"<<host;
	clients[j].hostName = std::string(host);
	clients[j].ipAddr = std::string(inet_ntoa(client_addr.sin_addr));
	clients[j].loginStatus = 1;
	clients[j].sendMsgNum = 0;
	clients[j].recvMsgNum = 0;
	clients[j].blockedNum = 0;
    // cout<<"\nvalue of j:"<<j+1;
	return j+1;
}