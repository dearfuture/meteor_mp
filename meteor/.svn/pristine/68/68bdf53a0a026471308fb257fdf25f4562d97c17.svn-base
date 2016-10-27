#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <stdio.h>        // for printf
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <time.h>                //for time_t and time
#include <arpa/inet.h>


#define SOCKS_VERSION_5		    0x05

#define SOCKS_AUTH_NONE				0x00
#define SOCKS_AUTH_USER_PASSWORD	0x01
#define SOCKS_AUTH_FLOW_PACKAGE		0x81

#define METHOD_GSSAPI		0x01
#define METHOD_NO_ACCEPT	0xFF

#define SOCKS_AUTH_VER      0x01
#define SOCKS_AUTH_OK       0x00

#define CMD_CONNECT			0x01
#define CMD_BIND			0x02
#define CMD_UDP				0x03

#define FIELD_RSV			0x00

#define ATYP_IPV4			0x01
#define ATYP_DOMAINNAME		0x03
#define ATYP_IPV6			0x04

#define SOCKS_STAGE_INIT 		1
#define SOCKS_STAGE_NEGOTIATION 2
#define SOCKS_STAGE_AUTH 		3
#define SOCKS_STAGE_COMMAND 	4
#define SOCKS_STAGE_CNT_REMOTE 	5
#define SOCKS_STAGE_DATA 		6
#define SOCKS_STAGE_CLOSE 		0


#define MAX_SOCKS_SESSION 3000
#define MAX_EVENTS 500  
#define RECV_BUF_SIZE 2048
#define SOCKET_ERROR -1
#define FILE_PATH_LENGTH 100

#define LOG_DIR "logs/test.log"
#define RESULT_DIR "logs/"

typedef struct config_file_s
{
	char * dest_ip;
	unsigned short dest_port;
	char * local_ip;
	char * dante_ip;
	unsigned short dante_port;
	char * username;
	char * orderAPPs;
	char * passwd;
	int issleep;
	int sleep_num;
	char * http_resource;
	int protocol;
	int connect_num;
	char * domain_name;
}config_file_t;



typedef struct socks_session_s
{
	int client_fd; //¿Í»§¶ËµÄsocket fd
	int client_udp_fd;

	unsigned char *remote_host;
	unsigned int remote_port;
	unsigned char *dante_host;
	unsigned int dante_port;
	unsigned char *local_host;

	unsigned char *dante_udp_host;
	unsigned int dante_udp_port;

	unsigned int local_udp_port;

	struct sockaddr_in server_udp_addr;
	socklen_t server_addr_UDP_length;

	long connect_stamp;  // stamp of connected
	long first_request_stamp; // stamp of first request from client
	//long first_response_stamp; // stamp of first reponse from remote
	long last_data_stamp; // last stamp of data send or recv	

	long tatal_recvdata;
	long file_datalen;
	int first_time;

	unsigned int stage;
	unsigned int protocol; // 1:tcp 0:udp
	unsigned short closed;
} socks_session_t;
//typedef struct socks_session_event_s  socks_session_event_t;

typedef struct socks_session_event_s
{    
    int fd;    
    void (*call_back)(int fd, int events, void *session);    
    int events;    
    socks_session_t *session;  
	unsigned char auth_method;
    unsigned char buf[RECV_BUF_SIZE];   // recv data buffer    
    ssize_t data_length;  // recv data length
    ssize_t sent_length;  // sent data length
    
	unsigned short eof;
	unsigned short closed;
}socks_session_event_t;  

typedef struct socks_worker_process_s
{
	int epoll_fd;
	socks_session_t sessions[MAX_SOCKS_SESSION];
	//fc_order_info_t orders[MAX_SOCKS_SESSION];
	int session_num;
} socks_worker_process_t;
 
//get current_time
long _get_current_ms()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((long)tv.tv_sec)*1000+((long)tv.tv_usec)/1000;
}

void _negotiation_cb (int client_fd, int events, void *arg);
void _accept_connect_cb(int listen_fd, int events, void *arg);
void _auth_cb (int client_fd, int events, void *arg);
void _command_cb (int client_fd, int events, void *arg);
void _tcp_data_transform_cb(int fd, int events, void *arg);
void _transform_data( int client_fd, int events, void *arg);
void _connect_remote_cb( int client_fd, int events, void *arg);
config_file_t * ReadConfig(const char* FileName,config_file_t * config);



