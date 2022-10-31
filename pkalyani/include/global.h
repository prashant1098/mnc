#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
using namespace std;
#define HOSTNAME_LEN 128
#define PATH_LEN 256


int createClient(int port);
void displayAuthor(char *command);
void displayIp(char *command, char *ip);
void displayPort(char *command, int port);
void getIpClient(char *ip);
void processResFromServer(char *command);
void updateStruct(char *tokens);
int login(char *command, int client_fd);
int addToClients(int fdaccept, struct sockaddr_in client_addr, int i, int client_port);
int isValidAddr(char *addr, char *port);

int createServer(int port);
void getIp(char *ip);
int authorCommand(char *command);
int ipCommand(char *ip, char *command);
int portCommand(char *command, int port);
int listCommand(char *command);
int processCmdFromClient(char *command, int sockIndex);
void sendLoginUserList(int sockIndex, char *command);
void sortList();
int searchIpClient(char *ip);

#endif
