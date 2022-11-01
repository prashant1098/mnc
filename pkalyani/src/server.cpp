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
	char hostname[256];
	char ip_addr[INET_ADDRSTRLEN];
	int portNo;
	char blockedList[20][INET_ADDRSTRLEN];
	int blockedNum;
    int loginStatus;
    int sendMsgNum;
    int recvMsgNum;
    char msgBuffer[100][1024];
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
    char ipAddr[20];
    maxIndex = server_fd;
    getIp(ipAddr);
    cout<<"\n server ip is:"<<ipAddr;
    while (true)
    {
        memcpy(&ready_socket, &current_socket, sizeof(current_socket));
        int selectReturn = select(maxIndex + 1, &ready_socket, NULL, NULL, NULL);
        if(selectReturn<0){
            // perror("Failure Select!!");
        }
        if(selectReturn>0){
            int i = 0;
            while(i<=maxIndex){
                if(FD_ISSET(i,&ready_socket)){
                    if(i==0){
                        char command[512];
                        char serverMsg[512];
                        memset(command, '\0', 512);
                        // getline(std::cin,command,'\n');
                        if(fgets(command, 512-1, stdin) == NULL) 
							exit(-1);
                        // printf("\nServer got: %s\n", command);
						command[strlen(command)-1]='\0';
                         if(strcmp(command, "AUTHOR") == 0){
                            authorCommand(command);
                        }
                         else if(strcmp(command, "IP") == 0){
                            ipCommand(ipAddr,command);
                         }
                         else if(strcmp(command, "PORT") == 0){
                            portCommand(command,PORT);
                         }
                         else if(strcmp("EXIT",command) == 0){
                            close(server_fd);
							exit(0);
                         }
                         else if(strcmp("LIST",command)==0){
                            listCommand(command);
                         }
                         else if(strcmp(command, "STATISTICS") == 0){

							cse4589_print_and_log("[%s:SUCCESS]\n", command);
							for (int i = 0; i < clientNo; i++){
								char stat[25];
								memset(stat,'\0',25);
								if(clients[i].socketId > 0){
									if(clients[i].loginStatus == 1){
										strcpy(stat,"logged-in");
									}
									else if(clients[i].loginStatus == 0){
										strcpy(stat,"logged-out");
									}
									else{
										continue;
									}
									cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", clients[i].no, clients[i].hostname, clients[i].sendMsgNum, clients[i].recvMsgNum, stat);
								}
							}
							cse4589_print_and_log("[%s:END]\n", command);  
						}
                        else if(strncmp(command, "BLOCKED", 7)==0){

							char *token;
							token = strtok(command," ");
							if(token!=NULL){
								token = strtok(NULL," ");
							}else{
								cse4589_print_and_log("[%s:ERROR]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);
								return 0;

							}
							char *check_b_ip;
							strcpy(check_b_ip,token);
							struct client blocklist[15];
							int n = 0;
							
							for (int i = 0; i < clientNo; i++){
								if(strcmp(clients[i].ip_addr,check_b_ip)==0){
									if(clients[i].blockedNum>0){
										for(int j = 0; j < clients[i].blockedNum;j++){
											printf("%s\n", clients[i].blockedList[j]);
											for (int m = 0; m < clientNo; m++){
												if(strcmp(clients[m].ip_addr,clients[i].blockedList[j])==0){
													strcpy(blocklist[n].hostname, clients[m].hostname);
													strcpy(blocklist[n].ip_addr, clients[m].ip_addr);
													blocklist[n].portNo = clients[m].portNo;
													n++;
													
												}
											}
										}
									}
								}
								
							}

                            struct client temp;
                            int i = 1;
                            int j, port;
                            while(i<n){
                                temp = blocklist[i];
                                j = i -1;
                                while(j>=0 && blocklist[j].portNo>temp.portNo){
                                    blocklist[j+1] = blocklist[j];
                                    j-=1;
                                }
                                blocklist[j+1]=temp;
                                i+=1;
                            }

							// struct client temp;
    						// for (int i = 0; i < n; i++){
    						// 	for (int j = i + 1; j < n; j++){
      						// 		if(blocklist[i].port_no>blocklist[j].port_no){
       						// 			temp = blocklist[i];
       						// 			blocklist[i] = blocklist[j];
       						// 			blocklist[j] = temp;
      
      						// 		}
     						// 	}
    						// }
    						cse4589_print_and_log("[%s:SUCCESS]\n", command);
    						for(int i = 0; i < n; i++){
    							cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",i+1,blocklist[i].hostname,blocklist[i].ip_addr,blocklist[i].portNo);
    						}
							cse4589_print_and_log("[%s:END]\n", command);  
						}
                    }
                    else if(i==server_fd){
                        // printf("\nAccepting connection");
                        struct sockaddr_in client_addr;
                        caddr_len = sizeof(client_addr);
                        fdaccept = accept(server_fd, (struct sockaddr *)&client_addr, &caddr_len);
                         if(fdaccept < 0){
                                //  printf("\nAccept failed");
                         }
                        FD_SET(fdaccept, &current_socket);
                        // printf("\nFD_SET");
                        clientNo = addToClients(fdaccept, client_addr, clientNo, 0);
                        if(fdaccept > maxIndex) maxIndex = fdaccept;
                    } 
                    else{
                        cout<<"\nReceiving command from client";
                        char buffer[1024];
                        memset(buffer,'\0',1024);
                        if(recv(i, buffer, 1024, 0) <= 0){
                                close(i);
                                // printf("\nRemote Host terminated connection!\n");
                                clientNo--;
                                FD_CLR(i, &current_socket);
                        }
                        else {
                                
                                processCmdFromClient(buffer, i);	                        	
                                fflush(stdout);
                        }
                        // free(buffer);
                    }
                }
                i+=1;
            }
        }
    }
    
    return 0;
}

int processCmdFromClient(char *command, int sockIndex){

	char *clientIp;
    int structIndex, i= 0;
    cout<<"\nsocket index:"<<sockIndex;
    while(i<clientNo){
        if(sockIndex==clients[i].socketId){
            clientIp = clients[i].ip_addr;
            structIndex = i;
            break;
        }
        i+=1;
    }
    char *cmd;
    char *token = strtok(command," ");
    if(token!=NULL){
        cmd = token;
        token = strtok(NULL," ");
    }
    else{
        cmd = command;
    }
    // printf("CMD:%s\n", cmd);

    if(strcmp("LOGOUT",cmd) == 0){
        clients[structIndex].loginStatus = 0;
        close(sockIndex);
        FD_CLR(sockIndex,&current_socket);
    }
    else if(strcmp("REFRESH",cmd) == 0){
        sortList();
        sendLoginUserList(sockIndex,"REFRESH");
    }
    else if(strcmp("PORT_SEND",cmd) == 0){
        cout<<"\n Inside port send";
        char tempArray[256];
        memset(tempArray, '\0', 256);
        strcpy(tempArray,token);
        clients[structIndex].portNo = atoi(tempArray);
        clients[structIndex].loginStatus = 1;
        cout<<"\nclient port number"<<clients[structIndex].portNo;
        sortList();
        sendLoginUserList(sockIndex,"CLIST");
    }
    else if(strcmp("SEND",cmd) == 0){
        char *senderIp;
        char message[1024];
        memset(message,'\0',1024);
        senderIp = token;
        strcat(message,"msg_send ");
        strcat(message,clientIp);
        strcat(message," ");
        if(token!=NULL){
            cmd = token;
            token = strtok(NULL," ");
         }
        while(token!=NULL){
            strcat(message,token);
            strcat(message," ");
            token = strtok(NULL," ");
        }
        fflush(stdout);
        printf("\nMessage on server side:%s",message);
        // printf("\nMessage on server side:%s for socket:%d",message,target_socket);
        

        int n = 0;
        int if_login = checkLogin(senderIp,structIndex);
        int if_block = checkBlock(senderIp,clientIp,structIndex);
        int target_socket;
		if(if_login == 1 && if_block == 0){
			target_socket = searchIpClient(senderIp);
			if(target_socket > 0){
				if(send(target_socket, message, strlen(message),0)>0){
					n++;
                    for (int i =0; i< clientNo;i++){
						if(strcmp(clients[i].ip_addr,senderIp)==0){
							clients[i].recvMsgNum++;
							clients[structIndex].sendMsgNum++;
							break;
						}
					}

					}
					fflush(stdout);
				}
		}
		else if(if_login == 0 && if_block == 0){
			if( target_socket = searchIpClient(senderIp)>0){
				for (int i =0; i< clientNo;i++){
					if(strcmp(clients[i].ip_addr,senderIp)==0&&clients[i].bufferMsg<100){
						strcpy(clients[i].msgBuffer[clients[i].bufferMsg],message);
						n++;
						clients[i].bufferMsg++;
						clients[structIndex].sendMsgNum++;
						break;
					}
				}
			}
		}
		else{
        	cse4589_print_and_log("[RELAYED:ERROR]\n");
        	cse4589_print_and_log("[RELAYED:END]\n");
		}

		if(n > 0){
			cse4589_print_and_log("[RELAYED:SUCCESS]\n");
			cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", clientIp, senderIp, message);
			cse4589_print_and_log("[RELAYED:END]\n");
		}else{
			cse4589_print_and_log("[RELAYED:ERROR]\n");
			cse4589_print_and_log("[RELAYED:END]\n");
		}
    }

    else if(strcmp("BLOCKIP",cmd) == 0){
        char ip[128];
        memset(ip,'\0',128);
        strcat(ip,token);
        strcat(clients[i].blockedList[clients[i].blockedNum],ip);
        clients[i].blockedNum+=1;
    }
    else if(strcmp("UNBLOCKIP",cmd) == 0){
        char ip[128];
        memset(ip,'\0',128);
        strcat(ip,token);
        for(int j=0;j<clients[structIndex].blockedNum;j++){
            if(strcmp(clients[structIndex].blockedList[j],ip)==0){
                bzero(clients[structIndex].blockedList[j],INET_ADDRSTRLEN);
                break;
            }
     }
    }
    else if (strcmp("BROADCAST",cmd) == 0){
    	int target = 0;
        char *token;
    	char message[1024];
    	memset(message,'\0',1024);
        int count = 0;
		strcat(message,"msg_broad ");
		strcat(message,clientIp);		
        strcat(message," ");
        token = strtok(cmd," ");
        while(token!=NULL){
            if(count!=0){
                strcat(message,token);
                strcat(message," ");
            }
            count+=1;
            token = strtok(NULL," ");
        }
        int counter=0;
		for(int i = 0; i < clientNo; i++){
			if(i != structIndex){
				target = clients[i].socketId;
				if((clients[i].loginStatus == 1) && (checkBlock(clients[i].ip_addr,clientIp,structIndex) == 0)){
					if(send(target, message, strlen(message),0)>0){
						counter++;
						clients[i].recvMsgNum++;
						clients[structIndex].sendMsgNum++;
						fflush(stdout);
					}
				}
				else if(clients[i].loginStatus == 0 && checkBlock(clients[i].ip_addr,clientIp,structIndex) == 0){
					for (int m =0; m< clientNo;m++){
						if(strcmp(clients[m].ip_addr,clients[i].ip_addr)==0&&clients[m].bufferMsg<100){
							strcpy(clients[m].msgBuffer[clients[m].bufferMsg],message);
							counter++;
							clients[m].bufferMsg++;
							clients[structIndex].sendMsgNum++;
						}
					}
				}
			}
		}
		if(counter>0){
			cse4589_print_and_log("[RELAYED:SUCCESS]\n");
			cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", clientIp, "255.255.255.255", message);
			cse4589_print_and_log("[RELAYED:END]\n");
		}else{
			cse4589_print_and_log("[RELAYED:ERROR]\n");
			cse4589_print_and_log("[RELAYED:END]\n");
		}
	}
    
    return 0;
   
}

int checkBlock(char *sender_ip,char *ip, int i){

			for (int j = 0; j < clients[i].blockedNum; j++){

				if(strcmp(clients[i].blockedList[j],sender_ip) == 0){
					return 1;
					break;
				}
        }
	return 0;
}

int checkLogin(char *ip, int j){
	
	for(int i = 0; i< clientNo; i++){
		
		if(strcmp(clients[i].ip_addr,ip) == 0 && clients[i].loginStatus == 1){
			return 1;
			break;
		}
		
	}
	return 0;
}

int searchIpClient(char *ip){
	int socket = 0;
	for(int i = 0; i< clientNo; i++){
		
		if(strcmp(clients[i].ip_addr,ip) == 0){
			socket = clients[i].socketId;
			return socket;
			break;
		}	
	}	
}


void sendLoginUserList(int sockIndex, char *command){
    cout<<"\nInside send login user list";
    char clientMessage[1024];
    memset(clientMessage, '\0', 1024);
    char message[1024];
    memset(message, '\0', 1024);
    char tempArray[256];
    int i =0;
    strcpy(clientMessage,command);
    strcat(clientMessage," ");
    while(i<clientNo){
        if(clients[i].loginStatus>0){
            // printf("\nclient no:%d",clients[i].no);
            memset(tempArray, '\0', 256);
            sprintf(tempArray,"%d",clients[i].no);
            strcat(clientMessage,tempArray);
            strcat(clientMessage,",");
            // clientMessage =  clientMessage + "hostname:" + clients[i].hostName;
            // printf("\nhost no:%s",clients[i].hostname);
            strcat(clientMessage,clients[i].hostname);
            strcat(clientMessage,",");
            // clientMessage =  clientMessage + "ip:" + clients[i].ipAddr;
            // printf("\nip no:%s",clients[i].ip_addr);
            strcat(clientMessage,clients[i].ip_addr);
            strcat(clientMessage,",");
            // clientMessage =  clientMessage + "port:" + to_string(clients[i].portNo);
            // printf("\nport no:%d",clients[i].portNo);
            memset(tempArray, '\0', 256);
            sprintf(tempArray,"%d",clients[i].portNo);
            strcat(clientMessage,tempArray);
            strcat(clientMessage," ");
        }
        i+=1;
    }
    cout<<"\nMessage for client:"<<clientMessage;
    strcpy(message, clientMessage);
    int check = send(sockIndex, message, sizeof(message), 0);
    // if(check>0){
    //     cout<<"\nDone "<<clientMessage;
    // }
    fflush(stdout);
}


	
void sortList(){
    cout<<"\nInside sort list";
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


int listCommand(char *command){
    cse4589_print_and_log("[%s:SUCCESS]\n", command);
    for (int i = 0; i < clientNo; i++){

        if(clients[i].loginStatus == 1){

            cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",clients[i].no,clients[i].hostname,clients[i].ip_addr,clients[i].portNo);

        }
    }
    cse4589_print_and_log("[%s:END]\n", command);  
    return 0;
}

int authorCommand(char *command){
    char ubName[10] = "pkalyani";
    cse4589_print_and_log("[%s:SUCCESS]\n", command); 
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", ubName);
	cse4589_print_and_log("[%s:END]\n", command);
    return 0;
}

int ipCommand(char *ip, char *command){

	cse4589_print_and_log("[%s:SUCCESS]\n", command);
	cse4589_print_and_log("IP:%s\n", ip);
	cse4589_print_and_log("[%s:END]\n", command);

	return 0;
}

int portCommand(char *command, int port){
    cse4589_print_and_log("[%s:SUCCESS]\n", command);
	cse4589_print_and_log("PORT:%d\n", port);
	cse4589_print_and_log("[%s:END]\n", command);
    return 0;
}

void getIp(char *ip){
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
    const char* p = inet_ntop(AF_INET, &name.sin_addr, ip, 80);
    if(p != NULL)
    {
        // printf("\nserver ip is:%s",ip);
    }
    else
    {
        // cout << "\nError number: " << errno;
    }

    close(sock);

}

int addToClients(int fdaccept, struct sockaddr_in client_addr, int j, int client_port){
	// printf("\nInside client");
    int i = 0;
    char *ip_addr = inet_ntoa(client_addr.sin_addr);
    while(i<clientNo){
        if(strcmp(clients[i].ip_addr,ip_addr)==0){
            return j;
        }
    }

	char host[1024];
	char service[20];
	clients[j].socketId = fdaccept;
	clients[j].no = j + 1;
	getnameinfo((struct sockaddr *) &client_addr, sizeof client_addr, host, sizeof host, service, sizeof service, 0);
    // printf("\nHost%s",host);
    // printf("\nIp:%s",ip_addr);
	strcpy(clients[j].hostname, host);
	strcpy(clients[j].ip_addr, ip_addr);
	clients[j].loginStatus = 1;
	clients[j].sendMsgNum = 0;
	clients[j].recvMsgNum = 0;
	clients[j].blockedNum = 0;
    // printf("\nvalue of j:%d",j);
	return j+1;
}