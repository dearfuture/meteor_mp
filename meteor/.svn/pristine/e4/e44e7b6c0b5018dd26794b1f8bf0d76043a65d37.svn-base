
/**************server.c******************/  
#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include "common.h"
#include <arpa/inet.h>
#define SERVERPORT 8082   /*服务器监听端口号*/  
#define BACKLOG 100  /*最大同时连接请求数*/  
#define BUFFER_SIZE 512  
#define SOCKET_ERROR -1
#define FILE_PATH_LENGTH 100


int main()  
{  
	//read config

	char file_path[FILE_PATH_LENGTH];
	getcwd(file_path, FILE_PATH_LENGTH);
	char filename[FILE_PATH_LENGTH];
	sprintf( filename,"%s/client.conf", file_path );
	FILE *file=fopen(filename, "r"); 
	//int SERVERPORT=CharsToInt(Search_config_file(file,"dest_ip"));
	//int BUFFER_SIZE=CharsToInt(ReadConfig(filename,"BUFFER_SIZE"));

	int sockfd,client_socket;  
	struct sockaddr_in my_addr;  
	struct sockaddr_in remote_addr;  
	int sin_size;  
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))==-1)  
	{  
		perror("socket 创建失败！");  
		exit(1);  
	}  
	my_addr.sin_family=AF_INET;  
	my_addr.sin_port=htons(SERVERPORT);  
	my_addr.sin_addr.s_addr=INADDR_ANY;  
	//bzero(&(my_addr.sin_zero),8);  
	if(bind(sockfd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr))==-1)  
	{  
		perror("bind出错！");  
		exit(1);  
	}  
	if(listen(sockfd,BACKLOG)==-1)  
	{  
		perror("listen 出错！");  
		exit(1);  
	}  
	static int N=0;
	while(1){  
		sin_size=sizeof(struct sockaddr_in);  
		if((client_socket=accept(sockfd,(struct sockaddr *)&remote_addr,&sin_size))==-1){  
			perror("accept error");  
			continue;  
		}
		int ret=0;
		long total_datasize=0;
		char buffer[BUFFER_SIZE];
		printf("收到一个连接来自：%s:%d\n",inet_ntoa(remote_addr.sin_addr),htons(remote_addr.sin_port));  
		//printf("收到一个连接来自：%s\n",inet_ntoa(remote_addr.sin_addr));  
		if(!fork()){ 
			while(1)
			{
				if(N==0)
				{
					ret=recv(client_socket,buffer,BUFFER_SIZE,0);
					printf("%d===========================================================\n",ret );
					total_datasize+=ret;
				}
				if(ret==SOCKET_ERROR)
				{
					printf("recv() 函数错误! \n");
					sleep(3);
					break;
				}
				if(ret==0)
					break;
				printf("recieve data size: %d\n",ret);
				buffer[ret]='\n';
				usleep(1000);
				ret=send(client_socket,buffer,ret,0);
				total_datasize+=ret;
				bzero(buffer,BUFFER_SIZE);
				printf("send data size: %d\n",ret);
			}
			printf("total_datasize of send and recieve:%d,ip is %s, prot is %d\n",total_datasize,inet_ntoa(remote_addr.sin_addr),htons(remote_addr.sin_port));
//			printf("%d\n", N);  
			close(client_socket);   
			exit(0);  
		}

		close(client_socket);  
	}  
} 
