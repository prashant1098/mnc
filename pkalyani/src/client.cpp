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

fd_set current_sock, ready_sock;
int clientNumber ;
struct clientside{
	int socketId;
	int no;
	string hostName;
	string ipAddr;
	int portNo;
	char blockedList[10][INET_ADDRSTRLEN];
	int blockedNum;
    int loginStatus;
    int sendMsgNum;
    int recvMsgNum;
    char msgBuffer[100][1024];
	int bufferMsg;
}clientArray[5];
int createClient(int PORT)
{
    string clientIp;
    vector <string> tokens;
    char serverMsgChar[1024];
    int sock = 0, valread, client_fd,maxIndex;
    struct sockaddr_in clientAddr;
    string serverMsg;
    FD_ZERO(&current_sock);
    FD_ZERO(&ready_sock);

    FD_SET(0, &current_sock);
    maxIndex = 0;
    clientIp = getIpClient();
    while(true){
        ready_sock = current_sock;
        int selectReturn = select(maxIndex+1,&ready_sock,NULL,NULL,NULL);
        if(selectReturn<0){
            perror("Failure Select!!");
        }
        if(selectReturn>0){
            int i = 0;
            string final;
            string command;
            while(i<=maxIndex){
                if(FD_ISSET(i,&ready_sock)){
                    if(i==0){
                        getline(std::cin,command,'\n');
                        if((command.compare(0,5,"LOGIN"))==0){
                            client_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if(client_fd<0){

                                perror("Failed to create socket");
                            }
                            serverMsg = "PORT_SEND " + to_string(PORT);
                            strcpy(serverMsgChar, serverMsg.c_str());
                            login(command, client_fd);
                            FD_SET(client_fd, &current_sock);
                            if(client_fd > maxIndex) maxIndex = client_fd;
                            if(send(client_fd, serverMsgChar,strlen(serverMsgChar),0) == strlen(serverMsgChar)) 
								printf("Done in port send!\n");
                            fflush(stdout);
                        }
                        else if((command.compare("AUTHOR"))==0){
                            displayAuthor(command);
                        }
                        else if((command.compare("IP"))==0){
                            displayIp(command,clientIp);
                        }
                        else if((command.compare("PORT"))==0){
                            displayPort(command,PORT);
                        }
                        else if((command.compare("REFRESH"))==0){
                            const char *str = "REFRESH";
							if(send(client_fd, str, strlen(str), 0) == strlen(str)){

								cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
								cse4589_print_and_log("[%s:END]\n", command.c_str());
							}
                        }
                        else if((command.compare("LOGOUT"))==0){
                            const char *str = "LOGOUT";
							if(send(client_fd,str, strlen(str), 0) == strlen(str)){

								close(client_fd);
								FD_CLR(client_fd,&current_sock);
								cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
								cse4589_print_and_log("[%s:END]\n", command.c_str());

							}
                        }
                        else if((command.compare("EXIT"))==0){
                            close(client_fd);
							exit(0);
                        }
                        else if((command.compare("LIST"))==0){
                                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
							
                                for (int i = 0; i < clientNumber; i++){
                                
                                        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",clientArray[i].no,clientArray[i].hostName.c_str(),clientArray[i].ipAddr.c_str(),clientArray[i].portNo);
                                                                    
                                    }
							    cse4589_print_and_log("[%s:END]\n", command.c_str());  
						    }
                        else if((command.compare(0,5,"BLOCK"))==0){
                            string commandBlock;
                            vector<string> tokens;
                            stringstream check1(command);
                            string intermediate;
                            while(getline(check1, intermediate, ' '))
                            {
                                tokens.push_back(intermediate);
                            }
                            commandBlock = "BLOCKIP " + tokens[1];
                            if(send(client_fd, commandBlock.c_str(),strlen(commandBlock.c_str()),0) == strlen(commandBlock.c_str())){
                                cout<<"\nBlock executed";
                                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
								cse4589_print_and_log("[%s:END]\n", command.c_str());
                            }
                        }
                        else if((command.compare(0,7,"UNBLOCK"))==0){
                            string commandBlock;
                            vector<string> tokens;
                            stringstream check1(command);
                            string intermediate;
                            while(getline(check1, intermediate, ' '))
                            {
                                tokens.push_back(intermediate);
                            }
                            commandBlock = "UNBLOCKIP " + tokens[1];
                            if(send(client_fd, commandBlock.c_str(),strlen(commandBlock.c_str()),0) == strlen(commandBlock.c_str())){
                                cout<<"\nUNBlock executed";
                                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
								cse4589_print_and_log("[%s:END]\n", command.c_str());
                            }
                        }
                    }
                    else{
                        // cout<<"\nValue of i is:"<<i;
                        char *buffer = (char*) malloc(sizeof(char)*1024);
                        memset(buffer, '\0', 1024);
                        if(recv(i, buffer, 1024, 0) <= 0){
                            close(i);
                            printf("EROROR\n");
                            FD_CLR(i, &current_sock);
                        }
                        else {
                        	char *cmd = buffer;
	                       	// printf("\nClient sent me: %s\n", cmd);
							processResFromServer(string(cmd));	                        	
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

int isValidAddr(string addr, string port){
    int ret = 1;
    int i =0;
    // cout<<"addr length:"<<addr.length()<<"port length:"<<port.length();
    while(i<addr.length()){
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
    while(i<port.length()){
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

void displayAuthor(string command){
    char ubName[10] = "pkalyani";
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str()); 
	cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", ubName);
	cse4589_print_and_log("[%s:END]\n", command.c_str());
}

void displayIp(string command, string ip){
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
	cse4589_print_and_log("IP:%s\n", ip.c_str());
	cse4589_print_and_log("[%s:END]\n", command.c_str());
}

void displayPort(string command, int port){
    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
	cse4589_print_and_log("PORT:%d\n", port);
	cse4589_print_and_log("[%s:END]\n", command.c_str());
}

std::string getIpClient(){
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
        cout<<"\nError no:"<<errno;
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
        cout << "\nError number: " << errno;
    }

    close(sock);
    return "";
}

void processResFromServer(string command){
    // cout<<"\nMessage from server:"<<command;
    vector <string> tokens;
    stringstream check1(command);
    string intermediate;
    while(getline(check1, intermediate, ' '))
    {
        tokens.push_back(intermediate);
    }
    if((tokens[0].compare("CLIST"))==0){
        updateStruct(tokens);
    }
    else if((tokens[0].compare("REFRESH"))==0){
        updateStruct(tokens);
    }
}

void updateStruct(vector<string> &tokens)
{
    clientNumber = 0;
        for(int i=1;i<tokens.size();i++){
            if(tokens[i]!=" ")
                {
                    vector <string> innerTokens;
                    stringstream check(tokens[i]);
                    string inter;
                    while(getline(check, inter, ','))
                    {
                        innerTokens.push_back(inter);
                    }
                    for(int i=0;i<innerTokens.size();i++){
                        vector <string> temp;
                        stringstream check2(innerTokens[i]);
                        string s;
                        while(getline(check2, s, ':'))
                        {
                            temp.push_back(s);
                        }
                        if (temp[0]=="no"){
                            clientArray[clientNumber].no = stoi(temp[1]);
                        }
                        else if(temp[0]=="hostname"){
                            clientArray[clientNumber].hostName = temp[1];
                        }
                        else if(temp[0]=="ip"){
                            clientArray[clientNumber].ipAddr = temp[1];
                        }
                        else if(temp[0]=="port"){
                            clientArray[clientNumber].portNo = stoi(temp[1]);
                        }
                        temp.clear();
                    }
                    clientNumber+=1 ;
                    innerTokens.clear();
                }  
        }
        // cout<<"\nServer side client list:"<<clientArray;
}


int login(string command, int client_fd){
    vector <string> tokens;
    stringstream check1(command);
    string intermediate;
    int loginPort;
    struct sockaddr_in remote_server_addr;
    while(getline(check1, intermediate, ' '))
    {
        tokens.push_back(intermediate);
    }
    if(tokens.size()<2){
        cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
        cse4589_print_and_log("[%s:END]\n", "LOGIN");
        return 0;
    }
    if(isValidAddr(tokens[1], tokens[2])==0){
    	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
        cse4589_print_and_log("[%s:END]\n", "LOGIN");
        return 0;
    }
    char login_address[tokens[1].length()];
    strcpy(login_address, tokens[1].c_str());
    loginPort = stoi(tokens[2]);
    

    bzero(&remote_server_addr, sizeof(remote_server_addr));
    remote_server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, login_address, &remote_server_addr.sin_addr);
    remote_server_addr.sin_port = htons(loginPort);
	int n = connect(client_fd, (struct sockaddr*)&remote_server_addr, sizeof(remote_server_addr));
    if(n<0){
        cout<<"\nConnection Failed";
    }
    return client_fd;
}