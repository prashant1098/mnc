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
#include<string.h>
#include <vector>
using namespace std;
#define HOSTNAME_LEN 128
#define PATH_LEN 256


int createClient(int port);
void displayAuthor(std::string command);
void displayIp(std::string command, string ip);
void displayPort(std::string command, int port);
std::string getIpClient();
void processResFromServer(std::string command);
void updateStruct(vector<string> &tokens);
int login(std::string cmd, int client_fd);
int addToClients(int fdaccept, struct sockaddr_in client_addr, int i, int client_port);
int isValidAddr(string addr, string port);

int createServer(int port);
std::string getIp();
int authorCommand(std::string command);
int ipCommand(std::string ip, std::string command);
int portCommand(int socket, std::string command, int port);
int listCommand(std::string command);
int processCmdFromClient(string command, int sockIndex);
void sendLoginUserList(int sockIndex, std::string command);
void sortList();

#endif
