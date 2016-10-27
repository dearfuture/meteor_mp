//     
// a simple echo server using epoll in linux    
//     
// by sparkling    
//     
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <netinet/in.h>    
#include <arpa/inet.h>    
#include <fcntl.h>    
#include <unistd.h>    
#include <stdio.h>    
#include <errno.h>  
#include <stdlib.h>  
#include <netdb.h>  
#include <string.h> 
#include "client.h"
#include "md5c.h"

#define MAX_SOCKS_SESSION 1024

#define MAX_EVENTS 500  

#define SOCKS_VERSION_5	0x05

#define SOCKS_AUTH_NONE				0x00
#define SOCKS_AUTH_USER_PASSWORD	0x02
#define SOCKS_AUTH_FLOW_PACKAGE		0x83

#define SOCKS_PROTOCOL_TCP 1
#define SOCKS_PROTOCOL_UDP 0

#define SOCKS_ATYP_IPV4 		0x01
#define SOCKS_ATYP_DOMAINNAME 	0x03
#define SOCKS_ATYP_IPV6 		0x04

#define SOCKS_COMMAND_CONNECT 		0x01
#define SOCKS_COMMAND_UDP_ASSOCIATE	0x03


#define SOCKS_STAGE_INIT 		1
#define SOCKS_STAGE_NEGOTIATION 2
#define SOCKS_STAGE_AUTH 		3
#define SOCKS_STAGE_COMMAND 	4
#define SOCKS_STAGE_CNT_REMOTE 	5
#define SOCKS_STAGE_DATA 		6
#define SOCKS_STAGE_CLOSE 		0
#define RECV_BUF_SIZE 1024

#define SOCKET_ERROR -1
#define FILE_PATH_LENGTH 100
#define PROCESS_NUM 100

#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)

//read config
char file_path[FILE_PATH_LENGTH];
char config_filename[FILE_PATH_LENGTH];
char system_log_array[100];
char buffer[2048];
//int process_num;

typedef struct socks_session_s
{
	int client_fd; //¿Í»§¶ËµÄsocket fd
//	int remote_fd; //Ô¶¶ËµÄsocket fd

//	int client_ready_events;
	int remote_ready_events;

	unsigned char *order_id;
	unsigned char *remote_host;
	unsigned int remote_port;
	unsigned char *dante_host;
	unsigned int dante_port;
	unsigned char *local_host;

	long connect_stamp;  // stamp of connected
	long first_request_stamp; // stamp of first request from client
	long first_response_stamp; // stamp of first reponse from remote
	long last_data_stamp; // last stamp of data send or recv
	
	int up_byte_num;
	int down_byte_num;
	long last_update_stamp; // last update time to redis

	unsigned int stage;
	unsigned int protocol; // 1:tcp 0:udp
} socks_session_t;

typedef struct fc_order_info_s 
{
	unsigned char *order_id;
	unsigned int order_status:8;
	unsigned int auth_error_num:8; // auth error times, if > 3, will frozen order
	
	long order_balance;
	long used_today;
	long company_balance;

	unsigned char *order_key;
	
} fc_order_info_t;


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
	int fail_times;
}socks_session_event_t;  

typedef struct socks_worker_process_s
{
	int epoll_fd;
	int listen_port;
	int listen_backlog;
	socks_session_t sessions[MAX_SOCKS_SESSION];
	fc_order_info_t orders[MAX_SOCKS_SESSION];
	int session_num;
} socks_worker_process_t;

typedef struct socks_command_reply_s
{
	int version:8;
	int status:8;
	int reserved:8;
	int atype:8;
} socks_command_reply_t;

// worker process global info
socks_worker_process_t process; 
socks_worker_process_t process_s[PROCESS_NUM];  

// set event    
void _register_session_event(int epoll_fd, socks_session_event_t *ev, int fd, int events, void (*call_back)(int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = ev;    
    epv.events = events;  
	
	ev->fd = fd;    
    ev->call_back = call_back;    

	int op = EPOLL_CTL_ADD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR("event add failed, fd:%d, evnets:%d", fd, events);    
	else	
		DEBUG_INFO("event add ok, fd:%d, evnets:%d", fd, events);	
} 


void _change_session_event(int epoll_fd, socks_session_event_t *ev, int fd, int events, void (*call_back)(int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = ev;    
    epv.events = events;  
	
	ev->fd = fd;    
    ev->call_back = call_back;    

	int op = EPOLL_CTL_MOD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
        DEBUG_ERR("event change failed, fd:%d, evnets:%d", fd, events);    
    else    
        DEBUG_INFO("event change ok, fd:%d, evnets:%d", fd, events);    
} 
// delete an event from epoll    
void _close_session(socks_session_event_t *ev)    
{    
	
	if( ev->session->client_fd > 0 )
	{
		close(ev->session->client_fd );
	}
	/*
	if( ev->session->remote_fd > 0 )
	{
		close(ev->session->remote_fd );
	}*/
	DEBUG_INFO("session closed ");	
	//FIXME: the following will segment fault
	//free( ev );
} 

// delete an event from epoll    
void _delete_session_event(int epoll_fd, socks_session_event_t *ev)    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = ev;    

	int op = EPOLL_CTL_DEL;
	
	if( ev->session->client_fd > 0 )
	{
		epoll_ctl(epoll_fd, op, ev->session->client_fd, &epv);
	}
		/*
	if( ev->session->remote_fd > 0 )
	{
		epoll_ctl(epoll_fd, op, ev->session->remote_fd, &epv);
	}*/
	DEBUG_INFO("session event deleted ");	
	ev->session->stage = SOCKS_STAGE_CLOSE;
	process.session_num--;
	_close_session( ev );
	
} 





void _negotiation_cb (int client_fd, int events, void *arg);

void _accept_connect_cb(int listen_fd, int events, void *arg);

void _auth_cb (int client_fd, int events, void *arg);

void _command_cb (int client_fd, int events, void *arg);

int _connect_remote_host_ipv4( socks_session_event_t *ev );

void _connect_remote_host_complete_cb(int remote_fd, int events, void *arg);

void _tcp_data_transform_cb(int fd, int events, void *arg);

void _transform_data( int client_fd, int events, void *arg);
void _connect_remote_cb( int client_fd, int events, void *arg);

int _recv_data ( socks_session_event_t *con, int size )
{
	int total = 0;	

	// see http://www.cnblogs.com/jingzhishen/p/3616156.html

	if( con->data_length >= RECV_BUF_SIZE| con->data_length <0 | 
			con->sent_length <0 | con->data_length < con->sent_length ){
		DEBUG_INFO( "begin recv, buf overflow, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
				con->data_length, con->sent_length,  size, total );
		return -1;
	}
	do{
		if( con->data_length >= RECV_BUF_SIZE| con->data_length <0 | 
				con->sent_length <0 | con->data_length < con->sent_length ){
			DEBUG_INFO( "buf overflow, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
					con->data_length, con->sent_length,  size, total );
			return -1;
		}
		int will_read = size;
		if( con->data_length+size >RECV_BUF_SIZE ){
			will_read = RECV_BUF_SIZE - con->data_length;
		}
		int len = recv(con->fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL

		if (len > 0)
		{
			con->data_length += len;
			total += len;
			return total;
		}
		else if( len < 0 )
		{
			int err = errno;
			if (err == EAGAIN)
			{	
//				DEBUG_INFO( "recv data EAGAIN : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
//					con->data_length, con->sent_length, size, total );
				break;
			}

			else if (err == EINTR| err == EWOULDBLOCK )
			{
				DEBUG_ERR( "recv data EINTR : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
					con->data_length, con->sent_length, size, total );
				continue;
			}
			else
			{
				DEBUG_ERR( "recv data error : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
					con->data_length, con->sent_length, size, total );
				return -1;
			}
		}
		else if( len == 0 ){ // Èç¹ûrecvº¯ÊýÔÚµÈ´ýÐ­Òé½ÓÊÕÊý¾ÝÊ±ÍøÂçÖÐ¶ÏÁË£¬ÄÇÃ´Ëü·µ»Ø0¡£
			DEBUG_ERR( "recv no data : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", con->fd, 
				con->data_length, con->sent_length, size, total );
			con->eof = 1;
			//break;
			return -1;
		}

	}
	while( 1 );
	
	return total;

}

int _recv_data_until_length( socks_session_event_t *con, int length )
{
	while( con->data_length < length)
	{
		int len = _recv_data ( con, length-con->data_length );

		if( len<=0 )
		{
	//		if(con->fail_times>=1000)
			break;
	//		con->fail_times++;
		}
	}
	con->fail_times=0;
	return con->data_length;
}

void _clean_recv_buf( socks_session_event_t *con )
{
	memset( con->buf, 0, RECV_BUF_SIZE );
	con->data_length = 0;
	con->sent_length = 0;
}

int _send_data( socks_session_event_t *con, int send_fd )
{
	int total = 0;	
	// will send size 
	int size = con->data_length-con->sent_length;
	if( size <=0 | size+con->sent_length>2048| con->sent_length < 0 | con->sent_length >=2048 | con->data_length<=0 | con->data_length>2048 ){
		DEBUG_INFO( "buf error, fd:%d, send_fd: %d, dlen:%d, slen:%d", con->fd, send_fd, con->data_length, con->sent_length );
		return -1;
	}
	
	do{
		int len = send(send_fd, &con->buf[con->sent_length], size, MSG_DONTWAIT ); //MSG_WAITALL
		if (len > 0)
		{
			con->sent_length += len;
			total += len;
			return total;
		}
		else if( len == 0 ){ 
			DEBUG_ERR( "net disconnected when send data. fd: %d", send_fd );
			return -1;
		}
		else{

			if (errno == EAGAIN)
			{
				DEBUG_INFO( "send data EAGAIN, fd: %d, dlen:%d, size:%d", send_fd, con->data_length, size );
				break;
			}

			if (errno == EINTR)
			{
				DEBUG_INFO( "send data EINTR, fd: %d", send_fd );
				size = con->data_length-con->sent_length;
				if( size > 0 )
					continue;
				else
					break;
			}
			DEBUG_ERR( "send data error, fd: %d", send_fd );
			return -1;
		}
	}
	while( 1 );
	
	return con->sent_length;

}

ssize_t _send_data_until_length( socks_session_event_t *con, int send_fd, ssize_t length )
{
	con->data_length = length;
	con->sent_length = 0;
	return _send_data(con, send_fd );
}

	

// negotiation method    
void _negotiation_cb (int client_fd, int events, void *arg)    
{    
    socks_session_event_t *ev = (socks_session_event_t*)arg;
    _clean_recv_buf(ev);

	if( ev->session->stage != SOCKS_STAGE_INIT && ev->session->stage != SOCKS_STAGE_NEGOTIATION ){
		printf( "%s: error stage: %d\n", __func__, ev->session->stage );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev );
		return;
	}
	if( ev->session->stage == SOCKS_STAGE_INIT ){
		memset( ev->buf, 0, sizeof(ev->buf) );
		ev->data_length = 0;
		ev->session->stage = SOCKS_STAGE_NEGOTIATION;
	}
	int len;
	//send auth method negotiation
	unsigned char methods[3] = { SOCKS_AUTH_FLOW_PACKAGE, SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_NONE };
	memset( ev->buf, 0, sizeof(ev->buf) );
	ev->buf[0]=SOCKS_VERSION_5;
	ev->buf[1]=3;
	memcpy(ev->buf+2,methods,3);
	//len = send( client_fd, ev->buf, 5, MSG_WAITALL );
	//len = send( client_fd, ev->buf, 5, 0 );
	len=_send_data_until_length(ev,client_fd,5);
	if(len<5)
	{
		DEBUG_INFO( "%d: auth method negotiation failed", time(NULL));
	}
	DEBUG_INFO( "%d: auth method negotiation", time(NULL));

	_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _auth_cb );

}//end _negotiation_cb

// auth callback
void _auth_cb (int client_fd, int events, void *arg)    
{    
	socks_session_event_t *ev = (socks_session_event_t*)arg;
	_clean_recv_buf(ev);
	if( ev->session->stage != SOCKS_STAGE_NEGOTIATION && ev->session->stage != SOCKS_STAGE_AUTH){
		printf( "%s: error stage: %d", __func__, ev->session->stage );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return;
	}

	if( ev->session->stage == SOCKS_STAGE_NEGOTIATION ){
		memset( ev->buf, 0, sizeof(ev->buf) );
		ev->data_length = 0;
		ev->session->stage = SOCKS_STAGE_AUTH;
	}
     //recieve auth method negotiation
	int len;
	len=_recv_data_until_length(ev,2);
	//len = recv(client_fd, ev->buf, 2, 0);
	if( len <= 0 ){
		//net disconnected. close session
		DEBUG_ERR( "disconnected when recv negotiation, len: %d", len );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return;
	}
	if( len < 2)
		return;
	if( ev->buf[0] != SOCKS_VERSION_5){
		printf( "%s: error version: %d", __func__, ev->buf[0] );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return ;
	}
	ev->auth_method=ev->buf[1];
	DEBUG_INFO( "%d: auth method : %x, stage: %x, ev:%x", time(NULL), ev->buf[1], ev->session->stage, ev->session  );


	printf( "%s: stage: %d\n", __func__, ev->session->stage );
	unsigned char auth_method = ev->auth_method;
	unsigned char method_version = 0x01;
	char *username=ReadConfig(config_filename,"username");
	char *passwd=ReadConfig(config_filename,"passwd");
	int cmd_choice=CharsToInt(ReadConfig(config_filename,"CMD"));
	char *orderkey=ReadConfig(config_filename,"orderAPPs");
	_clean_recv_buf(ev);
	ev->buf[0]=method_version;
	if(auth_method==SOCKS_AUTH_NONE)
	{
		_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
		return;
	}

	char AuthName[100];
	char AuthNameMD5[100];
	char AuthPasswd[16];
	char str_passwd[33];
	ev->session->protocol=cmd_choice;
	strcpy(AuthName,username);
	if(auth_method==SOCKS_AUTH_USER_PASSWORD)
	{
		strcpy(str_passwd,passwd);
	}
	else
	{
		switch(cmd_choice)
		{
			case 1:
			strcat(AuthNameMD5,ev->session->remote_host);
			break;
			case 3:
			strcat(AuthNameMD5,ev->session->local_host);
			break;
		}
		strcat(AuthNameMD5,passwd);
		strcat(AuthName,orderkey);
	    MD5_CTX md5;
	    MD5Init(&md5);
	    MD5Update(&md5, AuthNameMD5, strlen((char *)AuthNameMD5));
	    MD5Final(&md5, AuthPasswd);
	    MDString2Hex(AuthPasswd,str_passwd);
	}
	int iNameLen=strlen(AuthName);
	int iPasswd=strlen(str_passwd);
	ev->buf[1]=iNameLen;
	strcpy(ev->buf+2,AuthName);
	ev->buf[iNameLen+2]=iPasswd;
	strcpy(ev->buf+iNameLen+3,str_passwd);
	//SystemLog("UserName/PassWord req:\n",g_syslogfd);

	//len=send(client_fd,ev->buf,3+iNameLen+iPasswd,0);
	len=_send_data_until_length(ev,client_fd,3+iNameLen+iPasswd);
	DEBUG_INFO( "%d: UserName/PassWord req: %s:%s  %d", time(NULL), AuthName, str_passwd,len);
	_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
}

int _get_unsigned_int( unsigned char *p )
{
	return ((((int)p[0])&0x00ff) <<8) | (int)p[1];
}

struct in_addr _get_in_addr( unsigned char *p )
{
	struct in_addr ret ;
	//memset( ret, 0, sizeof( struct in_addr ) );
	memcpy( (void *)&ret, (void *)p,  sizeof( struct in_addr ) );
	return ret;
}

// command callback
void _command_cb (int client_fd, int events, void *arg)    
{   
	socks_session_event_t *ev = (socks_session_event_t*)arg;
	_clean_recv_buf(ev);
	DEBUG_INFO( "cmd from : %s:%d, stage:%x, ev:%x", ev->session->dante_host, ev->session->dante_port, ev->session->stage, ev->session );

	if( ev->session->stage != SOCKS_STAGE_AUTH && ev->session->stage != SOCKS_STAGE_COMMAND){
		DEBUG_ERR( "error stage: %d", ev->session->stage );
		close( client_fd );
		_delete_session_event( process.epoll_fd, ev );
		return;
	}
	if( ev->session->stage == SOCKS_STAGE_AUTH ){
		memset( ev->buf, 0, sizeof(ev->buf) );
		ev->data_length = 0;
		ev->session->stage = SOCKS_STAGE_COMMAND;
	}

	unsigned char auth_method = ev->auth_method;
	int method_version=0x01;
	int len;
	//sleep(1);
	//recieve authreq
	if(auth_method!=SOCKS_AUTH_NONE)
	{
		if(auth_method==SOCKS_AUTH_USER_PASSWORD)
		{
			len=_recv_data_until_length(ev,2);
			DEBUG_INFO( "%d: UserName/PassWord recv:  %d", time(NULL),len);
		}
		else
		{
			len=_recv_data_until_length(ev,19);
			DEBUG_INFO( "%d: UserName/PassWord recv:   %d", time(NULL), len);
		}
		if(len==SOCKET_ERROR)
		{
			//SystemLog("recv() error",g_syslogfd);
			//net disconnected. close session
			DEBUG_ERR( "disconnected when recv auth, len: %d", len );
			_delete_session_event( process.epoll_fd, ev );
			_close_session( ev->session );
		}
		if(len<2)
			return;
	    if( ev->buf[0] != method_version )
	    {
			printf( "%s: error method version: %d", __func__, ev->buf[0] );
			_delete_session_event( process.epoll_fd, ev );
			close( client_fd );
			return ;
		}
		if(ev->buf[1]!=0x00)
		{
			printf( "%s: order_status error: %d", __func__, ev->buf[1] );
			_delete_session_event( process.epoll_fd, ev );
			close( client_fd );
			return ;
		}

		if(len==19)
		{
			if(ev->buf[2]!=51)
			{
				printf( "%s: other_status error: %d", __func__, ev->buf[2] );
				_delete_session_event( process.epoll_fd, ev );
				close( client_fd );
				return ;
			}
			long long myBalance=Char2long(ev->buf+3);
			long long todayBalance=Char2long(ev->buf+11);
			DEBUG_INFO( "%d: myBalance : %lld", time(NULL), myBalance );
			DEBUG_INFO( "%d: todayBalance : %lld", time(NULL), todayBalance );
		}
		//DEBUG_INFO( "%d: UserName/PassWord req: %s:%s  %d", time(NULL), AuthName, str_passwd,len);
	} 

	_clean_recv_buf(ev);
	char *domain_name=ReadConfig(config_filename,"domain_name");
	int cmd_choice=CharsToInt(ReadConfig(config_filename,"CMD"));
	ev->buf[0]=SOCKS_VER;
	ev->buf[1]=cmd_choice;
	ev->buf[2]=FIELD_RSV;
	ev->buf[3]=ATYP_IPV4;
	//UDP? or TCP?
	unsigned short param_port=htons((short)ev->session->remote_port);
	int param_ip=(inet_addr(ev->session->remote_host));

	if(ev->buf[1]==CMD_UDP)
	{
		param_port=htons(4660);
		param_ip=inet_addr(ev->session->local_host);
	}
	int domainlen=strlen(domain_name);
	int connect_len=10;
	//char * recv_ip = inet_ntoa(*(struct in_addr*)(&param_ip));
	//unsigned short recv_port=ntohs(*(short*)( &param_port));
	//DEBUG_ERR( " error version  recv_port  recv_port: %s: %d",recv_ip,recv_port);
	switch(ev->buf[1])
	{
		case ATYP_IPV4:
		memcpy( (void *)&ev->buf+4, &param_ip,4);//ip
		memcpy( (void *)&ev->buf+8, &param_port,2);//port
		break;
		case ATYP_DOMAINNAME:
		ev->buf[4]=domainlen;
		strcpy(&ev->buf+5,domain_name);
		memcpy(&ev->buf+domainlen+5, &param_port,2);//port
		connect_len=domainlen+7;
		break;
	}
	len=_send_data_until_length(ev,client_fd,connect_len);
	DEBUG_ERR( "connect req send, len: %d", len );
	//recieve
	if( len ==SOCKET_ERROR ){
		//net disconnected. close session
		DEBUG_ERR( "connect req send failed, len: %d", len );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return;
	}
    _change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_remote_cb );
}




// connect remote host completed callback, then reply the result to client
// only for ipv4


void fc_stat_flow(socks_session_event_t *ev, int recv_len, int up_direct)
{
	//TOOD: check overflow
	long now = time(NULL);
	DEBUG_INFO( "%d: recv from : %s, bytes:%d", now, up_direct?"client":"remote", recv_len );
	if( up_direct ){
		ev->session->up_byte_num += recv_len;
		if( !ev->session->first_request_stamp ){
			ev->session->first_request_stamp = now;
		}
	}
	else{
		ev->session->down_byte_num += recv_len;
		if( !ev->session->first_response_stamp ){
			ev->session->first_response_stamp = now;
		}
	}
	ev->session->last_data_stamp = now;

}
//connect req
void _connect_remote_cb(int client_fd, int events, void *arg)
{
	socks_session_event_t *ev = (socks_session_event_t*)arg;
	_clean_recv_buf(ev);
	//DEBUG_INFO( "cmd from : %s:%d, stage:%x, ev:%x", ev->session->dante_host, ev->session->dante_port, ev->session->stage, ev->session );

	if( ev->session->stage != SOCKS_STAGE_CNT_REMOTE && ev->session->stage != SOCKS_STAGE_COMMAND){
		DEBUG_ERR( "error stage: %d", ev->session->stage );
		close( client_fd );
		_delete_session_event( process.epoll_fd, ev );
		return;
	}
	if( ev->session->stage == SOCKS_STAGE_COMMAND ){
		memset( ev->buf, 0, sizeof(ev->buf) );
		ev->data_length = 0;
		ev->session->stage = SOCKS_STAGE_CNT_REMOTE;
	}

	//recieve
	int len;
	memset( ev->buf, 0, sizeof(ev->buf) );
	len = _recv_data_until_length ( ev, 10 );
	//len = recv(client_fd,ev->buf,10,0);
	if(len<=0)
		return;
	DEBUG_ERR( "connect req recv, len: %d", len );
	if(len ==SOCKET_ERROR ){
		//net disconnected. close session
		DEBUG_ERR( "connect req recv failed, len: %d", len );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return;
	}
    if( ev->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( " error version: %d",  ev->buf[0] );
		_delete_session_event( process.epoll_fd, ev );
		close( client_fd );
		return ;
	}
	
	if( ev->buf[1] != 0x00){
		DEBUG_ERR( " username Authentication failed: %d",  ev->buf[1] );
		_delete_session_event( process.epoll_fd, ev );
		close( client_fd );
		return ;
	}
	_clean_recv_buf(ev);
	char http_file_path[100];
	char *test_result_fname=ReadConfig(config_filename,"test_result_fname");
	char *http_resource=ReadConfig(config_filename,"http_resource");//http_resource
	int is_sleep=CharsToInt(ReadConfig(config_filename,"sleep"));	
	int sleep_number=CharsToInt(ReadConfig(config_filename,"sleep_number"));
	int is_senddata=CharsToInt(ReadConfig(config_filename,"is_senddata"));//send data constant?
	int flen=GetHttpreq(file_path,ev->buf);
	len=_send_data_until_length(ev,client_fd,flen);
	DEBUG_ERR( "send data size of TCP: %d",  len );
	_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _transform_data );
}

void _transform_data( int client_fd, int events, void *arg) 
{
	socks_session_event_t *ev = (socks_session_event_t*)arg;

	if( ev->session->stage != SOCKS_STAGE_CNT_REMOTE ){
		DEBUG_ERR( "error stage: %d", ev->session->stage );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev->session );
		return;
	}
	char http_file_path[100];
	char *test_result_fname=ReadConfig(config_filename,"test_result_fname");
	char *http_resource=ReadConfig(config_filename,"http_resource");//http_resource
	int is_sleep=CharsToInt(ReadConfig(config_filename,"sleep"));	
	int sleep_number=CharsToInt(ReadConfig(config_filename,"sleep_number"));
	int is_senddata=CharsToInt(ReadConfig(config_filename,"is_senddata"));//send data constant?
	int len;
	if(!(events|EPOLLIN))
		return;
	_clean_recv_buf(ev);
	len=_recv_data_until_length(ev,153);
	//len=recv(client_fd,http_file_path,100,0);
	DEBUG_ERR( "recv data size of TCP: %d",  len );


	//total_datasize+=recvlen;	
	printf("%s\n",ev->buf);

	char savefilename[RECV_BUF_SIZE];
	sprintf( savefilename,"%s/", file_path );
	sprintf( savefilename,"%s", http_resource );
	FILE *save_file=fopen(savefilename,"wb");

	while(1)
	{
		if(is_senddata)
		{
			len=_send_data_until_length(ev,client_fd,RECV_BUF_SIZE);
			printf("senddatasize of io:%d\n",len);
		}
		bzero(ev->buf,RECV_BUF_SIZE);	
		len=_recv_data_until_length(ev,RECV_BUF_SIZE);	
		printf("recvdatasize of io:%d\n",len);
		if(len==SOCKET_ERROR)
		{
			printf("recv() error! \n");
			break;
		}
		if(len==0)
			break;

		if(is_sleep)
		{
			sleep(sleep_number);
		}
		fwrite(ev->buf,1,len,save_file);
		if(len<RECV_BUF_SIZE &&(!is_senddata))
		{
			printf("recvdata from server complete:%d\n",len);
			break;
		}
	}
	fclose(save_file);
	DEBUG_ERR( "disconnected when recv, len: %d", len );
	_delete_session_event( process.epoll_fd, ev );
	_close_session( ev->session );
	return;	
}

void _init_listen_socket(socks_session_event_t *ev)    
{    
	int client_fd = socket(AF_INET,SOCK_STREAM,0);   
    //fcntl(client_fd, F_SETFL, O_NONBLOCK); // set non-blocking    
    printf("client_fd =%d\n", client_fd); 
    ///initial sock

	struct sockaddr_in client_addr;
	bzero(&client_addr,sizeof(client_addr)); 
	client_addr.sin_family = AF_INET;    
	client_addr.sin_addr.s_addr = htons(INADDR_ANY);
	client_addr.sin_port = htons(0);    
	//
	if( client_fd < 0)
	{
		//SystemLog("Create Socket Failed!\n",g_syslogfd);
		//SystemLog("Create Socket Failed!\n",g_syslogfd);
		exit(1);
	}
	//
	if( bind(client_fd,(struct sockaddr*)&client_addr,sizeof(client_addr)))
	{
		///SystemLog("Client Bind Port Failed!\n",file_test_result);
		printf("Client Bind Port Failed!\n");
		exit(1);
	}

	process.session_num++;
	
	// find free session slot, should change session array to hashtable
	int i;
	for( i = 0; i<MAX_SOCKS_SESSION; i++)
	{
		if( process.sessions[i].stage == SOCKS_STAGE_CLOSE )
			break;
	}
	if( i == MAX_SOCKS_SESSION ){
		printf("%s: failed, already max connection:%d", __func__, MAX_SOCKS_SESSION); 
		close(client_fd);
        return;  
	}
	socks_session_t *session = &process.sessions[i];
	memset( session, 0, sizeof(socks_session_t) );
	
	session->client_fd = client_fd;
	session->dante_host = ReadConfig(config_filename,"dante_ip");
	session->dante_port = CharsToInt(ReadConfig(config_filename,"dante_port"));
	session->remote_host= ReadConfig(config_filename,"dante_ip");
	session->remote_port= CharsToInt(ReadConfig(config_filename,"dest_port"));
	//session->local_host= inet_ntoa(client_addr.sin_addr);
	session->connect_stamp = time(NULL);
	session->stage = SOCKS_STAGE_INIT;

	ev->session = session;

			//
	struct sockaddr_in server_addr;
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if(inet_aton(ev->session->dante_host,&server_addr.sin_addr) == 0) //
	{
		//SystemLog("Server IP Address Error!\n",g_syslogfd);
		//SystemLog("Server IP Address Error!\n",file_test_result);
		printf("Server IP Address Error!\n");
		exit(1);
	}
	server_addr.sin_port = htons(ev->session->dante_port);

	socklen_t server_addr_length = sizeof(server_addr);
	int connectlen=0;
	//
	if((connectlen=connect(client_fd,(struct sockaddr*)&server_addr, server_addr_length)) < 0)
	{
		printf("Can Not Connect To %s   %d!!!%d\n",ev->session->dante_host,ev->session->dante_port,client_fd);
		exit(1);
	}
	//_change_session_event( process.epoll_fd, ev, client_fd, EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );

	DEBUG_INFO( "%d: new connection from : %s:%d, stage:%x, ev:%x", ev->session->connect_stamp, ev->session->dante_host, ev->session->dante_port, ev->session->stage, ev->session );
	
	
	
	int flags = fcntl( client_fd, F_GETFL, 0);
	if (flags < 0) {
		printf( "%s: get socket flags error : %d, %s", __func__, errno, strerror(errno) );
		close( client_fd );
		return ;
	}
	// set nonblocking  
    int iret = 0;  
    if((iret = fcntl(client_fd, F_SETFL, flags|O_NONBLOCK)) < 0)  
    {  
        printf("%s: fcntl nonblocking failed: %d, %s", __func__, errno, strerror(errno));  
        close(client_fd);
        return;
    }
	printf("================================================================================");
	_register_session_event( process.epoll_fd, ev, client_fd, EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );
}    
  


int main(int argc, char **argv)    
{    
	memset( &process, 0, sizeof( process ) );
//	process.listen_port = 1080; // default port
//	process.listen_backlog = 100;
	getcwd(file_path, FILE_PATH_LENGTH);
	sprintf(config_filename,"%s/client.conf", file_path);
    if(argc == 2){    
        process.listen_port = atoi(argv[1]);    
    }
	
	if(argc == 3){    
        process.listen_backlog= atoi(argv[2]);    
    }

	// create epoll    
    process.epoll_fd = epoll_create(MAX_EVENTS);  

    if(process.epoll_fd <= 0) {
		DEBUG_ERR("create epoll failed.%d\n", process.epoll_fd );  
		exit(-1);
    }
    int sockd_fd;
    int sockd_num=100;
    int k=0;
    for(k=0;k<2;k++)
    {
    	int pid=fork();
    	if(pid<0)
    	{
    		printf("fork error\n");
            break;
    	}
    	else if(pid==0)
    	{
    		socks_session_event_t *ev=(socks_session_event_t *)malloc(sizeof(socks_session_event_t));
			memset( ev, 0, sizeof( socks_session_event_t ) );  
  			_init_listen_socket(&ev); 
  			sockd_fd=ev->fd;
    	}
    	else
    	{
    		DEBUG_ERR("fcntl nonblocking failed");  
		    close(sockd_fd);
		    return;
    	}
  		//printf("server running:port:%d, backlog:%d\n", process.listen_port, process.listen_backlog);
    } 
    /*
    for(k=0;k<sockd_num;k++)
    {
    	socks_session_event_t *ev=(socks_session_event_t *)malloc(sizeof(socks_session_event_t));
    	memset( ev, 0, sizeof( socks_session_event_t ) );  
  		_init_listen_socket(ev); 
    }*/
    // event loop    
    struct epoll_event events[MAX_SOCKS_SESSION];    

    int checkPos = 0;    
    while(1){    
        long now = time(NULL);    
		int i = 0;
        // wait for events to happen    
        process.session_num = epoll_wait(process.epoll_fd, events, MAX_SOCKS_SESSION, 1000); 
        DEBUG_INFO( "session_num : %d", process.session_num);   
        if(process.session_num < 0){    
            printf("epoll_wait error, exit\n");    
            break;    
        }
        for( i = 0; i < process.session_num; i++){    
            socks_session_event_t *sev = (socks_session_event_t*)events[i].data.ptr;    
            if(events[i].events&(EPOLLIN|EPOLLOUT) )     
            {    
                sev->call_back(sev->fd, events[i].events, sev ); 
            }
			else if((events[i].events&(EPOLLERR|EPOLLHUP) ))     
            {    
               DEBUG_ERR( "epoll error events: %d", events );
				_delete_session_event( process.epoll_fd, sev );
				_close_session( sev->session );
				free(sev);
				return;   
            } 
            //sleep();
            printf("%d\n", i);
        }
    }    
    // free resource 
    close( process.epoll_fd );
    return 0;    
}  

