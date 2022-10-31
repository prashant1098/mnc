#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
using namespace std;
#include "../include/global.h"
#include "../include/logger.h"

fd_set current_sock, ready_sock;
int clientNumber ;
struct clientside{
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
}clientArray[5];
int createClient(int PORT)
{
    char clientIp[20];
    char serverMsgChar[1024];
    int sock = 0, valread, client_fd,maxIndex;
    struct sockaddr_in clientAddr;
    string serverMsg;
    FD_ZERO(&current_sock);
    FD_ZERO(&ready_sock);

    FD_SET(0, &current_sock);
    maxIndex = 0;
    getIpClient(clientIp);
    // printf("\nclient ip%s",clientIp);
    while(true){
        ready_sock = current_sock;
        int selectReturn = select(maxIndex+1,&ready_sock,NULL,NULL,NULL);
        if(selectReturn<0){
            perror("Failure Select!!");
        }
        if(selectReturn>0){
            int i = 0;
            string final;
            while(i<=maxIndex){
                if(FD_ISSET(i,&ready_sock)){
                    if(i==0){
                        char command[512];
                        char serverMsg[512];
                        memset(command, '\0', 512);
                        // getline(std::cin,command,'\n');
                        if(fgets(command, 512-1, stdin) == NULL) 
							exit(-1);
                        // printf("\nClient got: %s\n", command);
						command[strlen(command)-1]='\0';
                        if(strncmp(command, "LOGIN", 5) == 0){
                            client_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if(client_fd<0){

                                perror("Failed to create socket");
                            }
                            char tempArray[256];
                            memset(serverMsg, '\0', 512);
                            memset(tempArray, '\0', 256);
                            sprintf(tempArray,"%d",PORT);
                            tempArray[strlen(tempArray)]='\0';
                            strcat(serverMsg,"PORT_SEND ");
                            strcat(serverMsg,tempArray);
                            // printf("\nPort: %s\n", tempArray);
                            serverMsg[strlen(serverMsg)]='\0';
                            login(command, client_fd);
                            FD_SET(client_fd, &current_sock);
                            if(client_fd > maxIndex) maxIndex = client_fd;
                            if(send(client_fd, serverMsg,strlen(serverMsg),0) == strlen(serverMsg)) 
								// printf("Done in port send!\n");
                            fflush(stdout);
                        }
                        else if(strcmp(command, "AUTHOR") == 0){
                            displayAuthor(command);
                        }
                        else if(strcmp(command, "IP") == 0){
                            displayIp(command,clientIp);
                        }
                        else if(strcmp(command, "PORT") == 0){
                            displayPort(command,PORT);
                        }
                        else if(strcmp(command, "REFRESH") == 0){
                            const char *str = "REFRESH";
							if(send(client_fd, str, strlen(str), 0) == strlen(str)){

								cse4589_print_and_log("[%s:SUCCESS]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);
							}
                        }
                        else if(strcmp(command, "LOGOUT") == 0){
                            const char *str = "LOGOUT";
							if(send(client_fd,str, strlen(str), 0) == strlen(str)){

								close(client_fd);
								FD_CLR(client_fd,&current_sock);
								cse4589_print_and_log("[%s:SUCCESS]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);

							}
                        }
                        else if(strcmp(command,"EXIT") == 0){
                            close(client_fd);
							exit(0);
                        }
                        else if(strcmp(command,"LIST") == 0){
                                cse4589_print_and_log("[%s:SUCCESS]\n", command);
							
                                for (int i = 0; i < clientNumber; i++){
                                
                                        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",clientArray[i].no,clientArray[i].hostname,clientArray[i].ip_addr,clientArray[i].portNo);
                                                                    
                                    }
							    cse4589_print_and_log("[%s:END]\n", command);  
						    }
                        else if(strncmp(command, "BLOCK", 5)==0){
                            char *token;
                            char *ip;
                            int counter = 0;
                            token = strtok(command," ");
                            while(token!=NULL){
                                if(counter=1){
                                    ip = token;
                                }
                                counter++;
                                token = strtok (NULL, " ");
                            }
                            char message[256];
                            memset(message,'\0',256);
                            strcat(message,"BLOCKIP");
                            strcat(message,ip);
                            if (send (client_fd, message, strlen(message), 0) > 0){
								// printf("Done in BLOCK\n");
								cse4589_print_and_log("[%s:SUCCESS]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);
							}
                        }
                        else if(strncmp(command, "UNBLOCK", 7)==0){
                            char *token;
                            char *ip;
                            int counter = 0;
                            token = strtok(command," ");
                            while(token!=NULL){
                                if(counter=1){
                                    ip = token;
                                }
                                counter++;
                                token = strtok (NULL, " ");
                            }
                            char message[256];
                            memset(message,'\0',256);
                            strcat(message,"UNBLOCKIP");
                            strcat(message,ip);
                            if(send(client_fd, message,strlen(message),0) == strlen(message)){
                                cout<<"\nUNBlock executed";
                                cse4589_print_and_log("[%s:SUCCESS]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);
                            }
                        }
                        else if(strncmp(command, "SEND", 4)==0){
                            printf("\ninside send");
                            char *token;
                            int counter=0;
                            char *input[1024];

                            token = strtok(command," ");
                            while(token!=NULL){
                                input[counter] = token;
                                counter+=1;
                                token = strtok(NULL," ");
                            }
                            
                            if(counter<2){
								cse4589_print_and_log("[%s:ERROR]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);	
								break;							
							}

                            char *targetIp ;
                            char message[1024];
                            memset(message,'\0',1024);
                            strcat(message,"SEND ");
                            strcat(message,input[1]);
                            strcat(message," ");
                            if(counter>=2){
                                for(int i=2;i<counter;i++){
                                    strcat(message,input[i]);
                                    strcat(message," ");
                                }
                            }
                            int flag = 1;
                            for(int i = 0;i<clientNumber;i++){
								if(strcmp(clientArray[i].ip_addr,input[1])==0){
									flag = 1;
									break;
								}
							}
                            if(flag > 0){
                                printf("\nMessage:%s",message);
								if (send (client_fd, message, strlen(message), 0) > 0){
									printf("Done in SEND\n");
									cse4589_print_and_log("[%s:SUCCESS]\n", command);
									cse4589_print_and_log("[%s:END]\n", command);
								}
							}
							else{
								cse4589_print_and_log("[%s:ERROR]\n", command);
								cse4589_print_and_log("[%s:END]\n", command);
							}
                        }
                    }
                    else{
                        // cout<<"\nValue of i is:"<<i;
                        char buffer[1024];
                        memset(buffer, '\0', 1024);
                        if(recv(i, buffer, 1024, 0) <= 0){
                            close(i);
                            // printf("EROROR\n");
                            FD_CLR(i, &current_sock);
                        }
                        else {
        
	                       	// printf("\nClient sent me: %s\n", buffer);
							processResFromServer(buffer);	                        	
							fflush(stdout);
                        }

                    }
                }
                i+=1;
            }
        }
    }
    return 0;
}

int isValidAddr(char addr[], char port[]){
    int ret = 1;
    int i =0;
    // cout<<"addr length:"<<addr.length()<<"port length:"<<port.length();
    while(i<INET_ADDRSTRLEN){
        if(addr[i] == '\0') break;
        if(addr[i] == '.'){
            i+=1;
            continue;
        }
        int t = addr[i] - '0';
        if(t<0 || t>9) {
            ret = 0;
            break;
        }
        i+=1;
    }
    i=0;
    while(i<512){
        if(port[i] == '\0') break;
        int t = port[i] - '0';
        if(t<0 || t>9) {
            ret = 0;
            break;
        }
        i+=1;
    }
    return ret;
}

void displayAuthor(char *command){
    char ubName[10] = "pkalyani";
    cse4589_print_and_log("[%s:SUCCESS]\n", command); 
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", ubName);
	cse4589_print_and_log("[%s:END]\n", command);
}

void displayIp(char *command, char *ip){
    cse4589_print_and_log("[%s:SUCCESS]\n", command);
	cse4589_print_and_log("IP:%s\n", ip);
	cse4589_print_and_log("[%s:END]\n", command);
}

void displayPort(char *command, int port){
    cse4589_print_and_log("[%s:SUCCESS]\n", command);
	cse4589_print_and_log("PORT:%d\n", port);
	cse4589_print_and_log("[%s:END]\n", command);
}

void getIpClient(char *ip){
    char* dnsServer = "8.8.8.8";
    int dnsPort = 53;

    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        std::cout << "Socket error" << std::endl;
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
        // printf("\nIp is:%s",ip);
    }
    else
    {
        // cout << "\nError number: " << errno;
    }

    close(sock);
}

void processResFromServer(char *command){
    // printf("Inside res from server %s",command);
    
    char *cmd;
    char *token = strtok(command," ");
    char *senderIp;
    if(token!=NULL){
        cmd = token;
        token = strtok(NULL," ");
    }
    // printf("CMD:%s\n", cmd);
    if(strcmp(cmd,"REFRESH") == 0){
        updateStruct(token);
    }
    else if(strcmp(cmd,"CLIST") == 0){
        updateStruct(token);
    }
    else if(strcmp(cmd,"msg_send") == 0){
        char *temp[10];
		int i = 0;
        char messageClient[1024];
        memset(messageClient,'\0',1024);
    	while( token != NULL){

			temp[i] = token;
			i++;
    		token = strtok (NULL, " ");

		}
		if(i<1){
			cse4589_print_and_log("[RECEIVED:ERROR]\n");
        	cse4589_print_and_log("[RECEIVED:END]\n");
		}
		if(i>=1){
			for(int j = 1; j < i; j++){
				strcat(messageClient,temp[j]);
				strcat(messageClient," ");
			}
		}
		cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
		cse4589_print_and_log("msg from:%s\n[msg]:%s\n", temp[0], messageClient);
		cse4589_print_and_log("[RECEIVED:END]\n");
    }
}

void updateStruct(char *tokens)
{
    clientNumber = 0;
    char temp[100];
    memset(temp,'\0',100);
    char *values[50];
    char *inner;
    // printf("\tokens:%s",tokens);
    while(tokens!=NULL){
        values[clientNumber]=tokens;
        clientNumber+=1;
        tokens = strtok (NULL, " ");
    }

    for(int i=0;i<clientNumber;i++){

        printf("\nValues:%s",values[i]);
        char *inner = strtok(values[i], ",");
        char *p[10];
        int j = 0 ;
        while(inner!=NULL){
            // printf("\nInner:%s",inner);
            p[j] = inner;
            inner = strtok(NULL, ",");
            j+=1;
        }
        int k =0 ;
        while(k<j){
            char *value = strtok(p[k], ":");
            char *key;
            if(value!=NULL){
                key = value;
                value = strtok(NULL, ":");
                // printf("\nvalue:%s",value);
                if(strcmp(key,"no")==0){
                    clientArray[i].no = atoi(value);
                    // printf("\n no:%d",clientArray[i].no);
                }
                else if(strcmp(key,"hostname")==0){
                    strcpy(clientArray[i].hostname,value);
                    // printf("\n hostname:%s",clientArray[i].hostname);
                }
                else if(strcmp(key,"ip")==0){
                    strcpy(clientArray[i].ip_addr,value);
                    // printf("\n ip_addr:%s",clientArray[i].ip_addr);
                }
                else if(strcmp(key,"port")==0){
                    clientArray[i].portNo = atoi(value);
                    // printf("\n portNo:%d",clientArray[i].portNo);
                }
            }
            k+=1;
        }
    }
        // cout<<"\nServer side client list:"<<clientArray;
}


int login(char *command, int client_fd){
    int loginPort;
    int counter = 0;
    char *token = strtok(command, " ");
    char *values[3];
    struct sockaddr_in remote_server_addr;
    while(token!=NULL){
        values[counter] = token;
        counter+=1;
        token = strtok(NULL, " ");
    }
    if(counter<2){
        cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
        cse4589_print_and_log("[%s:END]\n", "LOGIN");
        return 0;
    }
    cout<<"\nvalues"<<values[1]<<values[2];
    if(isValidAddr(values[1], values[2])==0){
    	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
        cse4589_print_and_log("[%s:END]\n", "LOGIN");
        return 0;
    }
    
    bzero(&remote_server_addr, sizeof(remote_server_addr));
    remote_server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, values[1], &remote_server_addr.sin_addr);
    remote_server_addr.sin_port = htons(atoi(values[2]));
	int n = connect(client_fd, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr));
    if(n<0){
        cout<<"\nConnection Failed";
    }
    return client_fd;
}