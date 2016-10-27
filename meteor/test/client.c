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
#include <pthread.h>

#if 1
#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#endif
#if 0
#define DEBUG_LINE() 
#define DEBUG_ERR(fmt, args...) 
#define DEBUG_INFO(fmt, args...) 
#endif
//read config
char file_path[FILE_PATH_LENGTH];
char system_log_file[100];
char system_log_array[100];
//char buffer[2048];
FILE *save_file;
int file_num;

// worker process global info

socks_worker_process_t process;
config_file_t * config;  
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
	if( ev->session->client_udp_fd > 0 )
	{
		close(ev->session->client_udp_fd );
	}
	ev->session->closed=1;
	free(ev);
	DEBUG_INFO("session closed ");	
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
	DEBUG_INFO("session event deleted ");	
	ev->session->stage = SOCKS_STAGE_CLOSE;
	process.session_num--;
	_close_session( ev );
	
}

config_file_t * ReadConfig(const char* FileName,config_file_t * config)  
{  
    config->dest_ip = Search_config_file(FileName,"dest_ip");
    config->dest_port = CharsToInt(Search_config_file(FileName,"dest_port"));
    config->local_ip = Search_config_file(FileName,"local_ip");
    config->dante_ip = Search_config_file(FileName,"dante_ip");
    config->dante_port = CharsToInt(Search_config_file(FileName,"dante_port"));
    config->username = Search_config_file(FileName,"username");

    config->orderAPPs = Search_config_file(FileName,"orderAPPs");
    config->passwd = Search_config_file(FileName,"passwd");
    config->domain_name = Search_config_file(FileName,"domain_name");
    config->issleep = CharsToInt(Search_config_file(FileName,"issleep"));
    config->sleep_num = CharsToInt(Search_config_file(FileName,"sleep_num"));
    config->http_resource = Search_config_file(FileName,"http_resource");
    config->protocol = CharsToInt(Search_config_file(FileName,"protocol"));
    config->connect_num = CharsToInt(Search_config_file(FileName,"connect_num"));
    return config;
} //end read_config

int _recv_data ( socks_session_event_t *con, int size )
{
	int total = 0;	

	// see http://www.cnblogs.com/jingzhishen/p/3616156.html
	if( con->data_length >= RECV_BUF_SIZE ){
		DEBUG_INFO( "[ %s:%d ] buf full,no recv, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", 
			__FILE__, __LINE__, con->fd, con->data_length, con->sent_length,  size, total );
		return 0;
	}
	if( con->data_length <0 || 
			con->sent_length <0 || con->data_length < con->sent_length ){
		DEBUG_INFO( "[ %s:%d ] begin recv, buf overflow, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", 
			__FILE__, __LINE__, con->fd, con->data_length, con->sent_length,  size, total );
		return -1;
	}

	do{
		int will_read = size;
		if( con->data_length+size >RECV_BUF_SIZE ){
			will_read = RECV_BUF_SIZE - con->data_length;
		}
		if(will_read <= 0)
			return 0;
		int len = 0;
		if(con->session->protocol == 3 && con->session->stage == SOCKS_STAGE_DATA)
		{
			len = recvfrom(con->session->client_udp_fd, con->buf, RECV_BUF_SIZE, 0, (struct sockaddr *)&(con->session->server_udp_addr), &(con->session->server_addr_UDP_length));
			DEBUG_ERR( "recv data EINTR : len: %d",len);

		}
		else
		{
			len = recv(con->fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL
		}
		//len = recv(con->fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL

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
			break;
		}
	}
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
	if( size <=0 | size+con->sent_length>RECV_BUF_SIZE| con->sent_length < 0 | con->sent_length >=RECV_BUF_SIZE | con->data_length<=0 | con->data_length>RECV_BUF_SIZE ){
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
		DEBUG_ERR( "error stage: %d\n", ev->session->stage );
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
	len=_send_data_until_length(ev,client_fd,5);
	if(len<5)
	{
		DEBUG_ERR( "%d: auth method negotiation failed", time(NULL));
	}
	DEBUG_INFO( "%d: auth method negotiation", time(NULL));
	ev->session->first_request_stamp=_get_current_ms();//get fistrequest time
	_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _auth_cb );

}//end _negotiation_cb

// auth callback
void _auth_cb (int client_fd, int events, void *arg)    
{    
	socks_session_event_t *ev = (socks_session_event_t*)arg;
	_clean_recv_buf(ev);
	if( ev->session->stage != SOCKS_STAGE_NEGOTIATION && ev->session->stage != SOCKS_STAGE_AUTH){
		DEBUG_ERR( "error stage: %d\n", ev->session->stage );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev );
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
		DEBUG_ERR( "disconnected when recv negotiation, len: %d", len );
		return;
	}
	if( len < 2)
		return;
	if( ev->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( "error version: %d", ev->buf[0] );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev );
		return ;
	}
	ev->auth_method=ev->buf[1];
	DEBUG_INFO( "%d: auth method : %x, stage: %x, ev:%x", time(NULL), ev->buf[1], ev->session->stage, ev->session  );

	unsigned char auth_method = ev->auth_method;
	unsigned char method_version = 0x01;
	char *username = config->username;
	char *passwd = config->passwd;
	int protocol = config->protocol;
	char *orderkey = config->orderAPPs;
	_clean_recv_buf(ev);
	ev->buf[0]=method_version;
	ev->session->protocol=protocol;
	if(auth_method==SOCKS_AUTH_NONE)
	{
		_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
		return;
	}

	char AuthName[100];
	char AuthNameMD5[100];
	char AuthPasswd[16];
	char str_passwd[33];
	strcpy(AuthName,username);
	if(auth_method==SOCKS_AUTH_USER_PASSWORD)
	{
		strcpy(str_passwd,passwd);
	}
	else
	{
		strcpy(AuthNameMD5,username);
		switch(protocol)
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
			_close_session( ev );
		}
		if(len<=0)
			return;
	    if( ev->buf[0] != method_version )
	    {
			DEBUG_ERR( "error method version: %d", ev->buf[0] );
			_delete_session_event( process.epoll_fd, ev );
			close( client_fd );
			return ;
		}
		if(ev->buf[1]!=0x00)
		{
			DEBUG_ERR( "order_status error: %d", ev->buf[1] );
			_delete_session_event( process.epoll_fd, ev );
			close( client_fd );
			return ;
		}

		if(len==19)
		{
			if(ev->buf[2]!=3)
			{
				DEBUG_ERR( "other_status error: %d", ev->buf[2] );
				_delete_session_event( process.epoll_fd, ev );
				close( client_fd );
				return ;
			}
			int myBalance=*(int *)(ev->buf+3);
			int todayBalance=*(int *)(ev->buf+7);
			long long companyBalance=*(long *)(ev->buf+11);
			DEBUG_INFO( "%d: myBalance : %d", time(NULL), myBalance );
			DEBUG_INFO( "%d: todayBalance : %d", time(NULL), todayBalance );
			DEBUG_INFO( "%d: todayBalance : %ld", time(NULL), companyBalance );
		}
	} 
	_clean_recv_buf(ev);
	char *domain_name = config->domain_name;
	int protocol = config->protocol;
	ev->buf[0]=SOCKS_VERSION_5;
	ev->buf[1]=protocol;
	ev->buf[2]=FIELD_RSV;
	ev->buf[3]=ATYP_IPV4;
	//UDP? or TCP?
	unsigned short param_port=htons((short)ev->session->remote_port);
	int param_ip=(inet_addr(ev->session->remote_host));
	if(ev->buf[1]==CMD_UDP)
	{
		int client_udp_fd = socket(AF_INET,SOCK_DGRAM,0);
		//set non-blocking  
		/*
		int flags = fcntl( client_udp_fd, F_GETFL, 0);
		if (flags < 0) {
			DEBUG_ERR( "get socket flags error : %d, %s", errno, strerror(errno) );
			close( client_udp_fd );
			return ;
		}
		 //set nonblocking  
	    int iret = 0;  
	    if((iret = fcntl(client_udp_fd, F_SETFL, flags|O_NONBLOCK)) < 0)  
	    {  
	        DEBUG_ERR("fcntl nonblocking failed: %d, %s",errno, strerror(errno));  
	        close(client_udp_fd);
	        return;
	    }*/
		ev->session->client_udp_fd=client_udp_fd;
		struct sockaddr_in client_udp_addr;
		bzero(&client_udp_addr,sizeof(client_udp_addr)); //
		client_udp_addr.sin_family = AF_INET;    //
		client_udp_addr.sin_addr.s_addr = htons(INADDR_ANY);//
		client_udp_addr.sin_port = htons(0); 
		
		if(bind(client_udp_fd,(struct sockaddr*)&client_udp_addr,sizeof(client_udp_addr))<0)
		{
			//SystemLog("UDP Bind Port Failed!\n",file_test_result);
			DEBUG_ERR("Client Bind Port Failed!\n");
			exit(1);
		}
		socklen_t addrsize = sizeof(client_udp_addr);	
		getsockname(client_udp_fd,(struct sockaddr*)&client_udp_addr,&addrsize);
		ev->session->local_udp_port = ntohs(client_udp_addr.sin_port);
		param_port=htons(ev->session->local_udp_port);
		param_ip=inet_addr(ev->session->local_host);
	}
	int domainlen=strlen(domain_name);
	int connect_len=10;

	switch(ev->buf[3])
	{
		case ATYP_IPV4:
		memcpy( (void *)&ev->buf+4, &param_ip,4);//ip
		memcpy( (void *)&ev->buf+8, &param_port,2);//port
		break;
		case ATYP_DOMAINNAME:
		ev->buf[4]=domainlen;
		memcpy(&ev->buf+5,domain_name,domainlen);
		memcpy(&ev->buf+domainlen+5, &param_port,2);//port
		connect_len=domainlen+7;
		break;
	}
	len=_send_data_until_length(ev,client_fd,connect_len);
	DEBUG_INFO( "connect req send, len: %d", len );
	//recieve
	if( len ==SOCKET_ERROR ){
		//net disconnected. close session
		DEBUG_ERR( "connect req send failed, len: %d", len );
		_delete_session_event( process.epoll_fd, ev );
		_close_session( ev );
		return;
	}
    _change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_remote_cb );
}
//connect req
void _connect_remote_cb(int client_fd, int events, void *arg)
{
	socks_session_event_t *ev = (socks_session_event_t*)arg;
	_clean_recv_buf(ev);
	DEBUG_INFO( "connect to : %s:%d, stage:%x, ev:%x", ev->session->remote_host, ev->session->remote_port, ev->session->stage, ev->session );

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
		_close_session( ev );
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
	ev->session->dante_udp_host = inet_ntoa(*(struct in_addr*)(ev->buf+4));
	ev->session->dante_udp_port = ntohs(*(short*)(ev->buf+8));

	_clean_recv_buf(ev);
	char http_file_path[100];
	int flen=GetHttpreq(config->http_resource,ev->session->remote_host,ev->buf);
	if(ev->session->protocol==CMD_UDP)
	{
		struct sockaddr_in server_udp_addr;
		server_udp_addr.sin_family=AF_INET;
		server_udp_addr.sin_addr.s_addr=inet_addr(ev->session->dante_udp_host);
		server_udp_addr.sin_port = htons(ev->session->dante_udp_port);
		socklen_t server_addr_UDP_length = sizeof(server_udp_addr);
		
		ev->session->server_udp_addr = server_udp_addr;
		ev->session->server_addr_UDP_length = server_addr_UDP_length;

		char *udpdata="udp test!!!";
		char * pCursor = ev->buf;
		*(short*)pCursor = 0;    // RSV  Reserved X'0000'
		pCursor += 2;
   
		*pCursor = 0; // Current fragment number
		pCursor++;
 
		*pCursor = 0x01;  // IP V4 address: X'01'
		pCursor ++;
		 
		int nIp = inet_addr( ev->session->remote_host );
		*(int*)pCursor = nIp;    // desired destination address
		pCursor += 4;
		 
		*(short*)pCursor = htons((short)ev->session->remote_port);
		pCursor += 2;
		 
		//message
		strcpy( pCursor, udpdata);
		pCursor += strlen(udpdata)+ 1;

		//printf("%d",ev->session->local_udp_port);
		DEBUG_INFO( "connect req recv failed, %s,%d",ev->session->remote_host,ev->session->remote_port);
		//strcpy(buffer+10,udpdata);
		len=sendto(ev->session->client_udp_fd,ev->buf,strlen(udpdata)+10,0,(struct sockaddr *)&server_udp_addr,server_addr_UDP_length);
		DEBUG_INFO( "sendlen of UDP:%d\n",len);
		//printf( "sendlen of UDP:%d\n",len);
	}
	else
	{
		len=_send_data_until_length(ev,client_fd,RECV_BUF_SIZE);
		DEBUG_INFO( "send data size of TCP: %d",  len );
	}
	_change_session_event( process.epoll_fd, ev, client_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _transform_data );
}

void _transform_data( int client_fd, int events, void *arg) 
{
	socks_session_event_t *ev = (socks_session_event_t*)arg;

	DEBUG_INFO( "transform data to : %s:%d, stage:%x, ev:%x", ev->session->remote_host, ev->session->remote_port, ev->session->stage, ev->session );

	if( ev->session->stage != SOCKS_STAGE_CNT_REMOTE && ev->session->stage != SOCKS_STAGE_DATA){
		DEBUG_ERR( "error stage: %d", ev->session->stage );
		close( client_fd );
		_delete_session_event( process.epoll_fd, ev );
		return;
	}
	if( ev->session->stage == SOCKS_STAGE_CNT_REMOTE ){
		memset( ev->buf, 0, sizeof(ev->buf) );
		ev->data_length = 0;
		ev->session->stage = SOCKS_STAGE_DATA;
	}

	char http_file_path[100];
	int len;
	if(!(events|EPOLLIN))
		return;
	DEBUG_INFO( "transform data to : %s:%d, stage:%x, ev:%x", ev->session->remote_host, ev->session->remote_port, ev->session->stage, ev->session );

	_clean_recv_buf(ev);

	if(ev->session->protocol==0x01)
	{
		if(ev->session->first_time==0)
		{
			len=recv(ev->fd,ev->buf,RECV_BUF_SIZE, MSG_PEEK);
			if(len<0)
				return;
			//printf("%s",ev->buf);
			DEBUG_INFO( "recv data size of TCP: %d",  len );
			len=GetHttpResponse(ev->buf);
			long filelen = GetHttpFileLen(ev->buf);
			
			if(filelen <= 0)
			{
				DEBUG_ERR( "recv httpresource failed: %d",  filelen );
			}
			ev->session->file_datalen = filelen;
			if(len>0)
			{
				len=_recv_data_until_length(ev,len+1);
				DEBUG_INFO( "recv data size of TCP: %d",  len );
			}
			ev->session->first_time = 1;
			return;
		}

		long will_read = ev->session->file_datalen - ev->session->tatal_recvdata;
		will_read = will_read < RECV_BUF_SIZE ? will_read : RECV_BUF_SIZE;
		len=_recv_data(ev,will_read);
		ev->session->tatal_recvdata += len;
		len=len=_send_data_until_length(ev,client_fd,RECV_BUF_SIZE);
		if(len>0 || ev->session->tatal_recvdata < ev->session->file_datalen)
			return;
	}

	else
	{
		/*
		if(len = recvfrom(ev->session->client_udp_fd, ev->buf, RECV_BUF_SIZE, 0, (struct sockaddr *)&(ev->session->server_udp_addr), &(ev->session->server_addr_UDP_length))>0)
		{
			DEBUG_ERR("recvlen of UDP %d\n",len);
			printf("recvlen of UDP %d\n",len);
			printf("%d\n", ev->buf[0]);
			ev->session->tatal_recvdata += len;
			return;
		}
		*/
		//len = _recv_data_until_length(ev,RECV_BUF_SIZE);
		DEBUG_ERR("recvlen of UDP %d\n",len);
		len = _recv_data ( ev, RECV_BUF_SIZE );
		DEBUG_ERR("recvlen of UDP %d\n",len);
		//printf("%s\n", ev->buf+10);
		//printf("recvlen of UDP %d\n",len);
		//printf("%d\n", ev->buf[0]);
		ev->session->tatal_recvdata += len;
		len=sendto(ev->session->client_udp_fd,ev->buf,RECV_BUF_SIZE,0,(struct sockaddr *)&ev->session->server_udp_addr,ev->session->server_addr_UDP_length);
		DEBUG_ERR("sendlen of UDP %d\n",len);
		return;
		//if(len>0)
		//return;
	}
	file_num++;
	ev->session->last_data_stamp = _get_current_ms();//get lastdata time
	ev->session->connect_stamp = ev->session->last_data_stamp-ev->session->first_request_stamp;
	memset(system_log_array,0,sizeof(system_log_array));
	if(ev->session->protocol==3)
	{
		if(ev->session->tatal_recvdata>=10)
			ev->session->tatal_recvdata -= 10;
	}
	sprintf(system_log_array,"%d、 fd: %d;tatal_recvdata: %ld;time_delay: %ld\n",file_num,ev->fd,ev->session->tatal_recvdata,ev->session->connect_stamp);
	SystemLog(system_log_array,save_file);
	DEBUG_INFO( "disconnected when recv, len: %d", len );
	_delete_session_event( process.epoll_fd, ev );
	return;	
}

void _init_listen_socket(socks_session_event_t *ev)    
{    
	int client_fd = socket(AF_INET,SOCK_STREAM,0);   
    //fcntl(client_fd, F_SETFL, O_NONBLOCK); // set non-blocking    
    ///initial sock 
	//
	if( client_fd < 0)
	{
		//SystemLog("Create Socket Failed!\n",g_syslogfd);
		//SystemLog("Create Socket Failed!\n",g_syslogfd);
		exit(1);
	}
	
	// find free session slot, should change session array to hashtable
	int i;
	for( i = 0; i<MAX_SOCKS_SESSION; i++)
	{
		if( process.sessions[i].stage == SOCKS_STAGE_CLOSE )
			break;
	}
	if( i == MAX_SOCKS_SESSION ){
		DEBUG_INFO(" failed, already max connection:%d", MAX_SOCKS_SESSION); 
		close(client_fd);
        return;  
	}
	process.session_num++;
	socks_session_t *session = &process.sessions[i];
	memset( session, 0, sizeof(socks_session_t) );
	
	session->client_fd = client_fd;
	session->dante_host = config->dante_ip;
	session->dante_port = config->dante_port;
	session->remote_host= config->dest_ip;
	session->remote_port= config->dest_port;
	session->local_host= config->local_ip;
	session->connect_stamp = time(NULL);
	session->stage = SOCKS_STAGE_INIT;

	ev->session = session;

	struct sockaddr_in server_addr;
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	if(inet_aton(ev->session->dante_host,&server_addr.sin_addr) == 0) //
	{
		DEBUG_ERR("Server IP Address Error!\n");
		exit(1);
	}
	server_addr.sin_port = htons(ev->session->dante_port);

	socklen_t server_addr_length = sizeof(server_addr);

	//set non-blocking 	
	int flags = fcntl( client_fd, F_GETFL, 0);
	if (flags < 0) {
		DEBUG_ERR( "get socket flags error : %d, %s", errno, strerror(errno) );
		close( client_fd );
		return ;
	}
	// set nonblocking  
    int iret = 0;  
    if((iret = fcntl(client_fd, F_SETFL, flags|O_NONBLOCK)) < 0)  
    {  
        DEBUG_ERR("fcntl nonblocking failed: %d, %s",errno, strerror(errno));  
        close(client_fd);
        return;
    }
	int connectlen=0;
	//
	if((connectlen=connect(client_fd,(struct sockaddr*)&server_addr, server_addr_length)) < 0)
	{
		if(errno != EINPROGRESS)
		{
			DEBUG_ERR("error   %d:::\n",errno);
			return;
		}
		fd_set set;  
	   	FD_ZERO(&set);  
	    FD_SET(client_fd,&set);  //相反的是FD_CLR(_sock_fd,&set)  
	  
		time_t timeout= 10;          //(超时时间设置为10毫秒)  
		struct timeval timeo;  
		timeo.tv_sec = timeout / 1000;   
		timeo.tv_usec = (timeout % 1000) * 1000;  
	  
	    int retval = select(client_fd + 1, NULL, &set, NULL, &timeo);           //事件监听  
	    if(retval < 0)     
	    {  
	        //建立链接错误close(_socket_fd) 
	        DEBUG_ERR("error   %d:::\n",errno);
	        return;
	    }  
	    else if(retval == 0) // 超时  
	    {  
	        //超时链接没有建立close(_socket_fd) 
	        DEBUG_ERR("Connection timeout \n");
			return; 
	    }  
	  
	     //将检测到_socket_fd读事件或写时间，并不能说明connect成功  
	    if(FD_ISSET(client_fd,&set))  
	    {  
	        int error = 0;  
	        socklen_t len = sizeof(error);  
	        if(error=getsockopt(client_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)  
	        {  
	                //建立简介失败close(_socket_fd)  
	           	DEBUG_ERR("error   %d:::\n",errno);
				exit(1); 
	        }  
	        if(error != 0) // 失败  
	        {  
	            //建立链接失败close(_socke
	           	DEBUG_ERR("error   %d:::\n",error);
				return; 
	        }  
	        else  
	        {  
	            DEBUG_INFO("connect success!!!\n");//建立链接成功  
	        }  
	    }  
	}

	DEBUG_INFO( "%d: new connection from : %s:%d, stage:%x, ev:%x", ev->session->connect_stamp, ev->session->dante_host, ev->session->dante_port, ev->session->stage, ev->session );
	_register_session_event( process.epoll_fd, ev, client_fd, EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );
} 


int main(int argc, char **argv)    
{    
	memset( &process, 0, sizeof( process ) );
	getcwd(file_path, FILE_PATH_LENGTH);
	char config_filename[FILE_PATH_LENGTH];
	sprintf(config_filename,"%s/client.conf", file_path);
	sprintf(system_log_file,"%s/logs/epoll_result.txt", file_path);
	//FILE * configfile=fopen(config_filename, "r");  
	config = (config_file_t *)malloc(sizeof(config_file_t));
	ReadConfig(config_filename,config);
	int connect_num = config->connect_num;
	save_file=fopen(system_log_file,"wb");

	int k=0;
	int sockd_fd;
	process.epoll_fd = epoll_create(MAX_EVENTS);  
	if(process.epoll_fd <= 0) {
		DEBUG_ERR("create epoll failed.%d\n", process.epoll_fd );  
		exit(-1);
	}
	
	for(k=0;k<connect_num;k++)
	{
		socks_session_event_t *ev=(socks_session_event_t *)malloc(sizeof(socks_session_event_t));
		memset( ev, 0, sizeof( socks_session_event_t ) );  
		_init_listen_socket(ev); 
	}
	// event loop    
	static struct epoll_event events[MAX_SOCKS_SESSION];    
	int checkPos = 0;    
	while(1){    
		long now = time(NULL);    
		int i = 0;
		// wait for events to happen    
		process.session_num = epoll_wait(process.epoll_fd, events, MAX_SOCKS_SESSION, 2000);
		if(process.session_num < 0){    
			DEBUG_ERR("epoll_wait error, exit \n");    
			break;    
		}
		//DEBUG_ERR("epoll_wait error, exit %d\n",process.session_num);
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
				_close_session( sev );
				free(sev);
				return;   
			}
			//usleep(1000);
		}
		if(process.session_num<=0)
			break;
	}    
		    // free resource 
	close( process.epoll_fd );
	return 0;    
}  

