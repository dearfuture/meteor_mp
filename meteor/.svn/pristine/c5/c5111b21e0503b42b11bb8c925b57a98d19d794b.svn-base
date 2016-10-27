//     
//  client for testing meteor(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
//  

#include <sys/types.h>
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <sys/ioctl.h>
#include <sys/timeb.h>
#include <sys/time.h>
#include <netinet/in.h>    
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <fcntl.h>    
#include <unistd.h>    
#include <stdio.h>    
#include <errno.h>  
#include <stdlib.h>  
#include <netdb.h>  
#include <string.h> 
#include <signal.h>
#include <time.h>
#include <stdarg.h>

#include "md5c.h"
#if 1
#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
//#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m\033[0m "#fmt" errno=%d, %m\r\n", ##args, errno, errno)
//#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#define DEBUG_INFO(fmt, args...) printf("\033[33m\033[0m "#fmt"\r\n", ##args)
#endif

#if 1
#define DEBUG_LINE() 
//#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_ERR(fmt, args...) 
//#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#define DEBUG_INFO(fmt, args...) 
#endif

#define MAX_SOCKS_SESSION	50000
#define MAX_EVENTS 			500  
#define RECV_BUF_SIZE		2048  

#define HOST_NAME_LEN	128  
#define FILE_NAME_LEN	512  
#define DOMAIN_LEN		256  

#define SOCKS_VERSION_5		0x05

#define SOCKS_AUTH_NONE				0x00
#define SOCKS_AUTH_USER_PASSWORD	0x02
#define SOCKS_AUTH_FLOW_PACKAGE		0x81

#define SOCKS_AUTH_ERR_ORDER_STATUS	0xfe    //order status not available

#define SOCKS_PROTOCOL_TCP	0x01
#define SOCKS_PROTOCOL_UDP	0x00

#define SOCKS_ATYPE_IPV4 	0x01
#define SOCKS_ATYPE_DOMAIN 	0x03
#define SOCKS_ATYPE_IPV6 	0x04

#define SOCKS_CMD_CONNECT 		0x01
#define SOCKS_CMD_UDP_ASSOCIATE	0x03

#define FILE_PATH_LENGTH 100

typedef struct socks_client_process_s socks_client_process_t;

typedef struct socks_client_connection_s socks_client_connection_t;

typedef struct socks_command_reply_s socks_command_reply_t;

typedef struct socks_string_s socks_string_t;

typedef union  socks_addr_u socks_addr_t;
typedef struct socks_host_s socks_host_t;


struct socks_client_process_s
{
	int epoll_fd;
	unsigned char cmd;
	
	char *sockd_ip;
	int sockd_port;
	int sockd_step;
	long last_connect_stamp;
	long connect_interval;

	char *remote_ip;
	int remote_port;

	char *local_ip;
	int local_udp_port;

	char *file_name;
	int file_len;

	int max_clients;
	
	int client_num;
	int max_cost_ms;
	int min_cost_ms;
	int success_num;
	long success_cost_ms;
	int fail_num;
	
	//for dante
	char *user;
	char *passwd;
	//for meteor
	char *token;
	char *app;
	char *orderkey;


	int closed_num;
	socks_client_connection_t *closed_connection[MAX_SOCKS_SESSION];
	//liu
	FILE *save_file;
	char test_log_array[FILE_PATH_LENGTH];
	//liu
	char *udpdata;
	/*
	int connect_num;
	int recv_com_data_num;*/
} ;


 struct socks_client_connection_s
{    
	int fd;    
	int local_port;
	int udp_fd;//liul
	int udp_local_port;//liul
	struct sockaddr_in sockd_udp_addr;
	socklen_t  sockd_udp_addr_len;
	unsigned char cmd;//liul
	int trans_stage;

	int events;
	void (*call_back)(socks_client_process_t *process, int fd, int events, void *arg);    

	unsigned char auth_method;
	unsigned char buf[RECV_BUF_SIZE];   // recv data buffer    
	ssize_t data_length;  // recv data length
	ssize_t sent_length;  // sent data length
	ssize_t recv_data_size;
	
    long connect_stamp;
    long first_request_stamp;
	long first_recv_ms;
	int cost_ms;
	int conn_ms;
	
	unsigned int eof:4;
	unsigned int closed:2;
	unsigned int protocol:2;

} __attribute__((aligned(sizeof(long))));



struct socks_string_s{
    size_t      len;
    u_char     *data;
};

union socks_addr_u {
   unsigned char      domain[DOMAIN_LEN];
   struct in_addr     ipv4;
   struct {
      struct in6_addr  ip;
      uint32_t         scopeid;
   } ipv6;
};

struct socks_host_s {
   unsigned char  atype;
   socks_addr_t   addr;
   in_port_t      port;
};

struct socks_command_reply_s
{
	unsigned char	version;
	unsigned char	status;
	unsigned char	reserved;
    socks_host_t	host;
};


int _init_client_socket( socks_client_process_t *process) ;
int _test_tcp_connect_result( int fd );
void _connect_socks_host_complete_cb(  socks_client_process_t *process, int fd, int events, void *arg) ;
void _negotiation_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _auth_cb( socks_client_process_t *process, int client_fd, int events, void *arg);
void _command_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _tcp_request_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _recv_tcp_response_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _udp_request_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _recv_udp_response_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _send_command( socks_client_process_t *process, int client_fd, int events, socks_client_connection_t *con) ;

long get_current_ms();


struct sockaddr_in *convert_to_sockaddr_in( socks_host_t *host, struct sockaddr_in *addr )
{
	memset( addr, 0, sizeof(struct sockaddr_in) );
	addr->sin_family = AF_INET;  
	addr->sin_port = host->port; 
	memcpy( &addr->sin_addr, &host->addr.ipv4, sizeof(host->addr.ipv4) );
	//addr->sin_addr = host->addr.ipv4;  
	return addr;
}

socks_host_t *convert_to_socks_host_t( socks_host_t *host, struct sockaddr_in *addr )
{
	host->atype = SOCKS_ATYPE_IPV4;
	memcpy( &host->addr.ipv4, &addr->sin_addr, sizeof(addr->sin_addr) );
	host->port = addr->sin_port;
	return host;
}

unsigned char *copy_host_to_hostname ( socks_host_t *host, unsigned char *hostname )
{
	char *hosta = inet_ntoa( host->addr.ipv4 );
	size_t hosta_len = strlen(hosta);
	memcpy( hostname, hosta, hosta_len );
	hostname[hosta_len]= '\0';
	return hostname;
}

unsigned char *copy_sockaddr_to_hostname ( struct in_addr *sin_addr, unsigned char *hostname )
{
	unsigned char * host = inet_ntoa(*sin_addr);
	size_t host_len = strlen(host);
	memcpy( hostname, host, host_len );
	hostname[host_len]= '\0';
	return hostname;
}


unsigned char * copy_socks_host_to_buf( socks_host_t *host, unsigned char *buf)
{
	/* ATYP */
	memcpy(buf, &host->atype, sizeof(host->atype));
	buf += sizeof(host->atype);

	switch (host->atype) {
	case SOCKS_ATYPE_IPV4:
		memcpy(buf, &host->addr.ipv4.s_addr, sizeof(host->addr.ipv4.s_addr));
		buf += sizeof(host->addr.ipv4.s_addr);
		break;

	case SOCKS_ATYPE_IPV6:
		memcpy(buf, &host->addr.ipv6.ip, sizeof(host->addr.ipv6.ip));
		buf += sizeof(host->addr.ipv6.ip);
		break;

	case SOCKS_ATYPE_DOMAIN:
		/* first byte gives length of rest. */
		*buf = (unsigned char)strlen(host->addr.domain);

		memcpy(buf + 1, host->addr.domain, (size_t)*buf);
		buf += *buf + 1;
		break;
	}

	/* DST.PORT */
	memcpy(buf, &host->port, sizeof(host->port));
	buf += sizeof(host->port);
	return (unsigned char *)buf;
}

unsigned char * copy_buf_to_socks_host(socks_host_t *host, unsigned char *buf)
{
	memcpy(&host->atype, buf, sizeof(host->atype));
	buf += sizeof(host->atype);

	switch (host->atype) {
		case SOCKS_ATYPE_IPV4:
			memcpy(&host->addr.ipv4, buf, sizeof(host->addr.ipv4)); // FIXME:XXXX
			buf += sizeof(host->addr.ipv4);
			break;

		case SOCKS_ATYPE_DOMAIN: {
			size_t domainlen = ((size_t)*buf )&0xff;
			buf += sizeof(*buf);
			memcpy(host->addr.domain, buf, domainlen);
			host->addr.domain[domainlen] = '\0';
			buf += domainlen;
			break;
		}

		case SOCKS_ATYPE_IPV6:
			memcpy(&host->addr.ipv6.ip, buf, sizeof(host->addr.ipv6.ip));
			buf += sizeof(host->addr.ipv6.ip);
			host->addr.ipv6.scopeid = 0;
			break;
	}
	
	memcpy(&host->port, buf, sizeof(host->port));
	buf += sizeof(host->port);
	return (unsigned char *)buf;
}


// set event    
void _register_session_event(int epoll_fd, socks_client_connection_t *con, int fd, int events, 
			void (*call_back)(socks_client_process_t *,int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;    
	epv.events = events;  
	
	con->fd = fd;    
	con->call_back = call_back;    

	int op = EPOLL_CTL_ADD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR( "[ %s:%d ] epoll add failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
	//else	
	//	DEBUG_INFO( "[ %s:%d ] epoll add ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);	
} 

void _change_session_event(int epoll_fd, socks_client_connection_t *con, int fd, int events, 
		void (*call_back)(socks_client_process_t *,int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;    
	epv.events = events;  
	
	con->fd = fd;    
	con->call_back = call_back;    

	int op = EPOLL_CTL_MOD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR( "[ %s:%d ] epoll change failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
	//else    
		//DEBUG_INFO( "[ %s:%d ] epoll change ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
} 

  
void _close_conenect( socks_client_process_t *process, socks_client_connection_t *con, int force )    
{    
	if( con->closed)
		return;
	
	con->closed = 1;

	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;    

	int op = EPOLL_CTL_DEL;
	if( epoll_ctl( process->epoll_fd, op, con->fd, &epv) < 0)
		DEBUG_ERR( "[ %s:%d ] epoll del failed, fd:%d", __FILE__, __LINE__, con->fd );    
	//else	
		//DEBUG_INFO( "[ %s:%d ] epoll del ok, fd:%d", __FILE__, __LINE__, con->fd );    

	if( con->fd > 0 ){
		if( force )
		{
			struct linger ling = {0, 0};
			if( setsockopt( con->fd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling) ) == -1 )
			{
				DEBUG_ERR( "[ %s:%d ] setsockopt(linger) failed, fd:%d", __FILE__, __LINE__, con->fd);	
			}
		}
		if( close(con->fd ) < 0 ){
			DEBUG_ERR( "[ %s:%d ] close socket failed, fd:%d", __FILE__, __LINE__, con->fd);   
		} 
		DEBUG_INFO( "[ %s:%d ] connect closed, fd:%d, recv_data_size:%d, client_num:%d", __FILE__, __LINE__, 
			con->fd, con->recv_data_size, process->client_num );	
		con->fd = 0;
	}
	process->client_num--;
	process->closed_connection[process->closed_num++] = con;
	
	DEBUG_INFO( "sum:file_len:%d, max_clients:%d, closed_num:%d, client_num:%d, max_cost_ms:%d, min_cost_ms:%d, avg_cost_ms:%d, succcess:%d, fail:%d ", 
		process->file_len, process->max_clients, process->closed_num, process->client_num, process->max_cost_ms, 
		process->min_cost_ms, process->success_num>0?(process->success_cost_ms/process->success_num):0,
		process->success_num, process->fail_num );
} 

   
int _recv_data ( socks_client_connection_t *con, int size )
{
	int total = 0;	

	// see http://www.cnblogs.com/jingzhishen/p/3616156.html

	if( con->data_length >= RECV_BUF_SIZE ){
		DEBUG_INFO( "[ %s:%d ] buf full,no recv, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
			con->fd, con->data_length, con->sent_length,  size, total );
		return 0;
	}
	if( con->data_length <0 || 
			con->sent_length <0 || con->data_length < con->sent_length ){
		DEBUG_INFO( "[ %s:%d ] begin recv, buf overflow, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
			con->fd, con->data_length, con->sent_length,  size, total );
		return -1;
	}
	do{
		int will_read = size;
		if( con->data_length+size >RECV_BUF_SIZE ){
			will_read = RECV_BUF_SIZE - con->data_length;
		}
		if( will_read <=0 ){
			DEBUG_ERR( "[ %s:%d ] recv size error, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
				con->fd, con->data_length, con->sent_length,  size, total );
			return 0;
		}
		int len;
		if(con->cmd == 3 && con->trans_stage == 1)
		{
			len = recvfrom(con->udp_fd, con->buf, RECV_BUF_SIZE, 0, (struct sockaddr *)&(con->sockd_udp_addr), &(con->sockd_udp_addr_len));
			//DEBUG_ERR( "recv data TCP : len: %d",len);

		}
		else
		{
			len = recv(con->fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL
		}

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
				DEBUG_ERR( "[ %s:%d ] recv data EAGAIN : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, con->fd, 
					con->data_length, con->sent_length, size, total );
				break;
			}

			else if (err == EINTR| err == EWOULDBLOCK )
			{
				DEBUG_ERR( "[ %s:%d ] recv data EINTR : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, con->fd, 
					con->data_length, con->sent_length, size, total );
				continue;
			}
			else
			{
				time_t now = time(NULL);
				struct tm *ptime = localtime(&now);
				char now_str[64];
				strftime(now_str, sizeof(now_str), "%Y-%m-%d %H:%M:%S", ptime);

				DEBUG_ERR( "[ %s:%d ] %s recv error. port:%d, fd:%d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, now_str, 
					con->local_port ,con->fd, con->data_length, con->sent_length, size, total );
				return -1;
			}
		}
		else if( len == 0 ){ // Èç¹ûrecvº¯ÊýÔÚµÈ´ýÐ­Òé½ÓÊÕÊý¾ÝÊ±ÍøÂçÖÐ¶ÏÁË£¬ÄÇÃ´Ëü·µ»Ø0¡£
			DEBUG_INFO( "[ %s:%d ] recv eof. fd:%d, dlen:%d, slen:%d, expect:%d, recv:%d, recv_data_size:%d", __FILE__, __LINE__, con->fd, 
				con->data_length, con->sent_length, size, total, con->recv_data_size );
			con->eof = 1;
			//break;
			return -1;
		}

	}
	while( 1 );
	
	return total;

}

int _recv_data_until_length( socks_client_connection_t *con, int length )
{
	while( con->data_length < length)
	{
		int len = _recv_data ( con, length-con->data_length );
		if( len<=0 )
			break;
	}
	return con->data_length;
}

void _clean_recv_buf( socks_client_connection_t *con )
{
	memset( con->buf, 0, RECV_BUF_SIZE );
	con->data_length = 0;
	con->sent_length = 0;
}

int _send_data( socks_client_connection_t *con, int send_fd )
{
	int total = 0;	
	// will send size 
	int size = con->data_length-con->sent_length;
	if( size <=0 | size+con->sent_length>RECV_BUF_SIZE|| con->sent_length < 0 || 
		con->sent_length >=RECV_BUF_SIZE || con->data_length<=0 || con->data_length>RECV_BUF_SIZE ){
		DEBUG_ERR( "[ %s:%d ] buf error, fd:%d, send_fd: %d, dlen:%d, slen:%d", __FILE__, __LINE__, con->fd, send_fd, 
			con->data_length, con->sent_length );
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
			DEBUG_ERR( "[ %s:%d ] net disconnected when send data. fd: %d, dlen:%d, slen:%d, size:%d", __FILE__, __LINE__, 
				send_fd, con->data_length, con->sent_length, size );
			return -1;
		}
		else{

			if (errno == EAGAIN)
			{
				DEBUG_ERR( "[ %s:%d ] send data EAGAIN, fd: %d, dlen:%d, size:%d", __FILE__, __LINE__, 
					send_fd, con->data_length, size );
				break;
			}

			if (errno == EINTR)
			{
				DEBUG_ERR( "[ %s:%d ] send data EINTR, fd: %d", __FILE__, __LINE__, send_fd );
				size = con->data_length-con->sent_length;
				if( size > 0 )
					continue;
				else
					break;
			}
			DEBUG_ERR( "[ %s:%d ] send data error, fd: %d", __FILE__, __LINE__, send_fd );
			return -1;
		}
		
	}
	while( 1 );
	
	return con->sent_length;

}

ssize_t _send_data_until_length( socks_client_connection_t *con, int send_fd, ssize_t length )
{
	con->data_length = length;
	con->sent_length = 0;
	return _send_data(con, send_fd );
}

// get current time, in ms
long get_current_ms()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((long)tv.tv_sec)*1000+((long)tv.tv_usec)/1000;
}


// call back for negotiation    
void _negotiation_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;

	int len;
	//send auth method negotiation
	unsigned char methods[3] = { SOCKS_AUTH_FLOW_PACKAGE, SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_NONE };

	_clean_recv_buf( con );

	con->buf[0]=SOCKS_VERSION_5;
	con->buf[1]=3;
	
	memcpy(con->buf+2,methods,3);
	con->data_length = 5;
	len=_send_data_until_length( con, client_fd, con->data_length);
	if(len<con->data_length)
	{
		DEBUG_INFO( "[ %s:%d ] auth method send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
	}
	if( len == con->data_length )
		_clean_recv_buf(con);
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _auth_cb );
		
	//liu
	//process->connect_num++;		
}


// auth callback, support SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_FLOW_PACKAGE
void _auth_cb( socks_client_process_t *process, int client_fd, int events, void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	con->cmd=process->cmd;//liul

	int len;    
	int will_read = 2;
	len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv negotiation result, len: %d", __FILE__, __LINE__, len );
		_close_conenect( process, con, 1);
		return;
	}
	if( con->data_length < will_read)
		return;

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_INFO( "[ %s:%d ] error version: %d",  __FILE__, __LINE__, con->buf[0] );
		_close_conenect( process, con, 1);
		return ;
	}
	con->auth_method = con->buf[1];
	//DEBUG_INFO( "[ %s:%d ] auth method : %x", __FILE__, __LINE__, con->buf[1]  );

	if(con->auth_method==SOCKS_AUTH_NONE)
	{
		_send_command( process, client_fd, events, con );
		return;
	}

	_clean_recv_buf(con);
	
	int i=0;
	con->buf[i++]=0x01;
	if(con->auth_method==SOCKS_AUTH_USER_PASSWORD)
	{
		int ulen = strlen( process->user);
		con->buf[i++]=ulen;
		memcpy( &con->buf[i], process->user, ulen);
		i+=ulen;
		int plen = strlen( process->passwd);
		con->buf[i++]=plen;
		memcpy( &con->buf[i], process->passwd, plen);
		con->data_length = i+plen;
	}
	else
	{
		char tmp[256];
		char passwd_bytes[16]={0};
		char passwd_hex_str[33]={0};
		memset(tmp, 0, sizeof(tmp) );
		sprintf( tmp, "%s/%s", process->token, process->app );
		
		int ulen = strlen( tmp);
		con->buf[i++]=ulen;
		memcpy( &con->buf[i], tmp, ulen);
		i+=ulen;
		
		memset(tmp, 0, sizeof(tmp) );
		memset(passwd_bytes, 0, sizeof(passwd_bytes) );
		memset(passwd_hex_str, 0, sizeof(passwd_hex_str) );
		switch(process->cmd)
		{
			case SOCKS_CMD_CONNECT:
				sprintf( tmp, "%s%s%s", process->token, process->remote_ip, process->orderkey);
				break;
			case SOCKS_CMD_UDP_ASSOCIATE:
				sprintf( tmp, "%s%s%s", process->token, process->local_ip, process->orderkey );
				break;
		}
	    MD5_CTX md5;
	    MD5Init(&md5);
	    MD5Update(&md5, tmp, strlen((char *)tmp));
	    MD5Final(&md5, passwd_bytes);
	    MDString2Hex(passwd_bytes,passwd_hex_str);

		int plen = strlen( passwd_hex_str);
		con->buf[i++]=plen;
		memcpy( &con->buf[i], passwd_hex_str, plen);
		con->data_length = i+plen;
		//DEBUG_INFO( "[ %s:%d ]UserName/PassWord req: %s,%s",  __FILE__, __LINE__, &con->buf[2], passwd_hex_str );
		 
	}

	len=_send_data_until_length(con,client_fd,con->data_length);
	//DEBUG_INFO( "[ %s:%d ]UserName/PassWord req: %s  slen:%d",  __FILE__, __LINE__,  &con->buf[2], len);
	if( len == con->data_length )
		_clean_recv_buf(con);
	else
		DEBUG_INFO( "[ %s:%d ] auth send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
				
}

// command callback
void _command_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;

	if(con->auth_method!=SOCKS_AUTH_NONE)
	{
		//if( !(events & EPOLLIN) )
		//	return;

		int len;    
		int will_read = 19;
		if(con->auth_method==SOCKS_AUTH_USER_PASSWORD)
		{
			will_read = 2;
		}

		len = _recv_data_until_length ( con, will_read );
		DEBUG_INFO( "[ %s:%d ]0x%x method, auth recv: %d",  __FILE__, __LINE__, con->auth_method, len);

		if( len < 0 || con->eof ){
			//net disconnected. close session
			DEBUG_ERR( "[ %s:%d ] disconnected when recv auth result, len: %d", __FILE__, __LINE__, len );
			_close_conenect( process, con, 1);
			return;
		}
		if( con->data_length < will_read)
			return;

		if( con->buf[0] != 0x01 ){
			DEBUG_INFO( "[ %s:%d ] error version: %d",	__FILE__, __LINE__, con->buf[0] );
			_close_conenect( process, con, 1);
			return ;
		}
		unsigned int status =con->buf[1];
		//DEBUG_INFO( "[ %s:%d ]auth status : %x", __FILE__, __LINE__, status  );
		if( status != 0 ){
			DEBUG_ERR( "[ %s:%d ] auth fail, status: 0x%x, orderstatus:%d", __FILE__, __LINE__, status, con->buf[2] );
			_close_conenect( process, con, 1);
			return ;
		}	

	}

	_send_command( process, client_fd, events, con );

				
}

void _send_command (  socks_client_process_t *process, int client_fd, int events, socks_client_connection_t *con)    
{    
	_clean_recv_buf(con);
	con->buf[0] = SOCKS_VERSION_5;
	con->buf[1] = process->cmd;
	con->buf[2] = 0x00;
	
	socks_host_t host;
	memset( &host, 0, sizeof(host) );
	
	if( process->cmd == SOCKS_CMD_CONNECT ){
		host.atype = 0x01;	//ipv4
		inet_aton( process->remote_ip, &host.addr.ipv4);  
		host.port= htons(process->remote_port);  
	}
	if( process->cmd == SOCKS_CMD_UDP_ASSOCIATE){
				//udp fd
		int client_udp_fd = socket(AF_INET,SOCK_DGRAM,0);
		
		//set non-blocking  
		
		int flags = fcntl( client_udp_fd, F_GETFL, 0);
		if (flags < 0) {
			//DEBUG_ERR( "get socket flags error : %d, %s", errno, strerror(errno) );
			close( client_udp_fd );
			return ;
		}		
		 //set nonblocking  
		int iret = 0;  
		if((iret = fcntl(client_udp_fd, F_SETFL, flags|O_NONBLOCK)) < 0)  
		{  
			//DEBUG_ERR("fcntl nonblocking failed: %d, %s",errno, strerror(errno));  
			close(client_udp_fd);
			return;
		}

		int value = 1;
		if (setsockopt( client_udp_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
		{
			DEBUG_ERR("set udp SO_REUSEADDR fail, fd:%d",  client_udp_fd );
		}
		
		con->udp_fd=client_udp_fd;
		struct sockaddr_in client_udp_addr;
		bzero(&client_udp_addr,sizeof(client_udp_addr)); //
		client_udp_addr.sin_family = AF_INET;    //
		client_udp_addr.sin_addr.s_addr = htons(INADDR_ANY);//
		client_udp_addr.sin_port = htons(0); 
		if(bind(client_udp_fd,(struct sockaddr*)&client_udp_addr,sizeof(client_udp_addr))<0)
		{
			DEBUG_ERR( "[ %s:%d ] bind udp_fd fail", __FILE__, __LINE__ );
			return;
		}
		socklen_t addrsize = sizeof(client_udp_addr);	
		getsockname(client_udp_fd,(struct sockaddr*)&client_udp_addr,&addrsize);
		con->udp_local_port = ntohs(client_udp_addr.sin_port);

		host.atype = 0x01;	//ipv4
		inet_aton( process->local_ip, &host.addr.ipv4);  
		host.port= htons(con->udp_local_port);  
	}
	unsigned char *pos = copy_socks_host_to_buf( &host,&con->buf[3] );
	con->data_length = pos - &con->buf[0];
	
	int len=_send_data_until_length(con,client_fd,con->data_length);
	DEBUG_INFO( "[ %s:%d ]cmd req: 0x%x  slen:%d",__FILE__, __LINE__, con->buf[2], len );
	if( len == con->data_length )
		_clean_recv_buf(con);
	else
		DEBUG_INFO( "[ %s:%d ] cmd send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
	if( process->cmd == SOCKS_CMD_CONNECT ){
		_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _tcp_request_cb );
	}
	if( process->cmd == SOCKS_CMD_UDP_ASSOCIATE ){
		_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _udp_request_cb );
	}

				
}

// command callback
void _tcp_request_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	socks_command_reply_t reply;
	
	memset( &reply, 0, sizeof(reply) );
	
	int will_read =  10; // just test for ipv4
	int len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv cmd reply, fd:%d", __FILE__, __LINE__, client_fd );
		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		DEBUG_INFO( "[ %s:%d ] recv cmd reply, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( "[ %s:%d ]  error socks version: %d, fd:%d", __FILE__, __LINE__,  con->buf[0], client_fd );
		_close_conenect( process, con, 1);
		return ;
	}
	memcpy( &reply, con->buf, 3 );
	copy_buf_to_socks_host( &reply.host ,&con->buf[3]);

	_clean_recv_buf(con);

	sprintf( con->buf, "GET /%s HTTP/1.1\r\nHOST: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0\r\n\r\n",
		process->file_name, process->remote_ip );
	
	con->data_length = strlen( con->buf );
	con->first_request_stamp = get_current_ms();
	len=_send_data_until_length(con,client_fd,con->data_length);
	//DEBUG_INFO( "[ %s:%d ]send cmd req, slen:%d", __FILE__, __LINE__,  len );
	if( len == con->data_length )
		_clean_recv_buf(con);
	else
		DEBUG_INFO( "[ %s:%d ] req send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _recv_tcp_response_cb );			
}

// command callback
void _udp_request_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	socks_command_reply_t reply;
	
	memset( &reply, 0, sizeof(reply) );
	
	int will_read =  10; // just test for ipv4
	int len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv cmd reply, fd:%d", __FILE__, __LINE__, client_fd );
		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		DEBUG_INFO( "[ %s:%d ] recv cmd reply, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( "[ %s:%d ]  error socks version: %d, fd:%d", __FILE__, __LINE__,  con->buf[0], client_fd );
		_close_conenect( process, con, 1);
		return ;
	}
	memcpy( &reply, con->buf, 3 );
	copy_buf_to_socks_host( &reply.host ,&con->buf[3]);
	//con->udp_sockd_port = &reply.host.port;
	_clean_recv_buf(con);
	struct sockaddr_in server_udp_addr;
	server_udp_addr.sin_family=AF_INET;
	server_udp_addr.sin_addr = reply.host.addr.ipv4;
	server_udp_addr.sin_port = reply.host.port;
	socklen_t server_addr_UDP_length = sizeof(server_udp_addr);
	con->sockd_udp_addr = server_udp_addr;
	con->sockd_udp_addr_len = server_addr_UDP_length;

	char * pCursor = con->buf;
	*(short*)pCursor = 0;    // RSV  Reserved X'0000'
	pCursor += 2;
	*pCursor = 0; // Current fragment number
	pCursor++;
	*pCursor = 0x01;  // IP V4 address: X'01'
	pCursor ++;
	int nIp = inet_addr( process->remote_ip);
	*(int*)pCursor = nIp;    // desired destination address
	pCursor += 4;
	*(short*)pCursor = htons((short)process->remote_port);
	pCursor += 2;
	//message
	strcpy( pCursor, process->udpdata);
	pCursor += strlen(process->udpdata)+ 1;
	DEBUG_INFO( "[ %s:%d ]  connect req to udp,remote_host: %s, fd:%d", __FILE__, __LINE__,process->remote_ip,process->remote_port);
	len=sendto(con->udp_fd,con->buf,strlen(process->udpdata)+10,0,(struct sockaddr *)&server_udp_addr,server_addr_UDP_length);
	DEBUG_ERR( "[ %s:%d ]  sendlen of udp: %d", __FILE__, __LINE__,len);
	_register_session_event( process->epoll_fd, con, con->udp_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _recv_udp_response_cb );
}

void _recv_udp_response_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	con->trans_stage=1;

	_clean_recv_buf(con);

	socks_command_reply_t reply;
	
	memset( &reply, 0, sizeof(reply) );
	long now = get_current_ms();
	
	int will_read =  RECV_BUF_SIZE; 
	//liul
	int len = recvfrom(con->udp_fd, con->buf, RECV_BUF_SIZE,0, (struct sockaddr *)&(con->sockd_udp_addr), &(con->sockd_udp_addr_len));
	if( len > 0 ){
		con->recv_data_size += len;
		
		if( con->first_recv_ms <=0 ){
			con->first_recv_ms = (now-con->first_request_stamp);
		}
/*
		len=sendto(con->udp_fd,con->buf,RECV_BUF_SIZE,0,(struct sockaddr *)&(con->sockd_udp_addr),con->sockd_udp_addr_len);
			return;*/
		
		//liul
		if(con->recv_data_size < process->file_len)
		{
			len=sendto(con->udp_fd,con->buf,RECV_BUF_SIZE,0,(struct sockaddr *)&(con->sockd_udp_addr),con->sockd_udp_addr_len);
			return;
		}
	}
	if( len < 0 || con->eof ){
		con->cost_ms = (now-con->first_request_stamp);
		con->conn_ms = (now-con->connect_stamp);
		if( con->recv_data_size > process->file_len ){
			process->success_num++;
			process->success_cost_ms += con->cost_ms;
			if( con->cost_ms > process->max_cost_ms )
				process->max_cost_ms = con->cost_ms;
			if( con->cost_ms < process->min_cost_ms )
				process->min_cost_ms = con->cost_ms;
		}
		else{
			process->fail_num++;
		}
		//net disconnected. close session
		DEBUG_INFO( "[ %s:%d ] recv data finished, fd:%d, recv_data_size:%d, first_recv_ms:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
			client_fd, con->recv_data_size, con->first_recv_ms, con->cost_ms, con->conn_ms );
		//liu
		/*
		memset(process->test_log_array,0,sizeof(process->test_log_array));
		sprintf(test_log_array,"connect_num:%d; fd: %d;tatal_recvdata: %ld;first_recv_ms:%d; cost_ms:%d; conn_ms:%d\n",
			process->connect_num,client_fd,con->recv_data_size, con->first_recv_ms, con->cost_ms, con->conn_ms);
		fwrite(process->test_log_array,strlen(process->test_log_array),1,process->save_file);
  		fflush(process->save_file);
		//SystemLog(test_log_array,save_file);*/

		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		//DEBUG_INFO( "[ %s:%d ] recv data, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}
				
}




// command callback
void _recv_tcp_response_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	_clean_recv_buf(con);

	socks_command_reply_t reply;
	
	memset( &reply, 0, sizeof(reply) );
	long now = get_current_ms();
	
	int will_read =  RECV_BUF_SIZE; 
	int len = _recv_data ( con, will_read );
	if( len > 0 ){
		con->recv_data_size += len;
		
		if( con->first_recv_ms <=0 ){
			con->first_recv_ms = (now-con->first_request_stamp);
		}
	}
	if( len < 0 || con->eof ){
		con->cost_ms = (now-con->first_request_stamp);
		con->conn_ms = (now-con->connect_stamp);
		if( con->recv_data_size > process->file_len ){
			process->success_num++;
			process->success_cost_ms += con->cost_ms;
			if( con->cost_ms > process->max_cost_ms )
				process->max_cost_ms = con->cost_ms;
			if( con->cost_ms < process->min_cost_ms )
				process->min_cost_ms = con->cost_ms;
		}
		else{
			process->fail_num++;
		}
		//net disconnected. close session
		DEBUG_INFO( "[ %s:%d ] recv data finished, fd:%d, recv_data_size:%d, first_recv_ms:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
			client_fd, con->recv_data_size, con->first_recv_ms, con->cost_ms, con->conn_ms );
		//liu
		/*
		memset(process->test_log_array,0,sizeof(process->test_log_array));
		sprintf(test_log_array,"connect_num:%d; fd: %d;tatal_recvdata: %ld;first_recv_ms:%d; cost_ms:%d; conn_ms:%d\n",
			process->connect_num,client_fd,con->recv_data_size, con->first_recv_ms, con->cost_ms, con->conn_ms);
		fwrite(process->test_log_array,strlen(process->test_log_array),1,process->save_file);
  		fflush(process->save_file);
		//SystemLog(test_log_array,save_file);*/

		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		//DEBUG_INFO( "[ %s:%d ] recv data, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}
				
}


int _init_client_socket( socks_client_process_t *process)    
{    
	int fd = socket(AF_INET, SOCK_STREAM, 0); 
	if( fd == -1 ){
		DEBUG_ERR( "[ %s:%d ] open socket fail, fd:%d", __FILE__, __LINE__, fd );
		return -1;
	}

		
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;	 
	inet_aton( process->sockd_ip, &sin.sin_addr);  
	sin.sin_port = htons(process->sockd_port);  

	int reuseaddr = 1;
	if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (void *) &reuseaddr, sizeof(int)) == -1){
		DEBUG_ERR( "[ %s:%d ] get SO_REUSEADDR fail, fd=%d\n", __FILE__, __LINE__, fd); 
	}

    int flags = fcntl( fd, F_GETFL, 0);
    if (flags < 0) {
		DEBUG_ERR( "[ %s:%d ] get socket flags error, fd=%d\n", __FILE__, __LINE__, fd); 
		return -1;
    }

	if( fcntl(fd, F_SETFL, flags |O_NONBLOCK) < 0 ){ // set non-blocking    
		DEBUG_ERR( "[ %s:%d ] set O_NONBLOCK failed, fd=%d\n", __FILE__, __LINE__, fd); 
		return -1;
	}

	socks_client_connection_t *con = (socks_client_connection_t *)malloc(sizeof(socks_client_connection_t));
	if( con == NULL ){
		DEBUG_ERR( "[ %s:%d ] malloc error,fd: %d", __FILE__, __LINE__, fd );
		return -1;
	}
	memset( con, 0, sizeof(socks_client_connection_t) );
	con->connect_stamp = get_current_ms();
	con->fd = fd;
	
	int ret = connect( fd, (struct sockaddr*) &sin, sizeof (struct sockaddr));
	process->client_num++;
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			DEBUG_ERR( "[ %s:%d ] connect sockd error, fd:%d, %s:%d", __FILE__, __LINE__, fd,  
				process->sockd_ip, process->sockd_port );
			_close_conenect( process, con, 1 );
			return -2;
		}
	}
	else if(ret == 0 ){
		_change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );
		return fd;
	}
	
	_register_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_socks_host_complete_cb );
	return fd;
	
} 

int _test_tcp_connect_result( int fd )
{
    int err = 0;
    socklen_t len = sizeof(int);

    /*
     * BSDs and Linux return 0 and set a pending error in err
     * Solaris returns -1 and sets errno
    */

    if (getsockopt( fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1)
    {
        err = errno;
    }

    return err;
}


void _connect_socks_host_complete_cb(  socks_client_process_t *process, int fd, int events, void *arg)   
{

    socks_client_connection_t *con = (socks_client_connection_t*)arg;
	int error = _test_tcp_connect_result( fd );
	if( error ){
		DEBUG_ERR( "[ %s:%d ] connect sockd error:%s, fd:%d, %s:%d, events:0x%x", __FILE__, __LINE__, 
			strerror(error), fd,  process->sockd_ip, process->sockd_port, events );
		if (error != EINPROGRESS) {
			_close_conenect(  process, con, 1 );
			return ;
		}
		return;
	}

	// connect successfully  
    if( events & (EPOLLOUT ) ){  
		struct sockaddr_in local_addr; 
		socklen_t len = sizeof(local_addr);
		getsockname( fd, (struct sockaddr*)&local_addr, &len);
		con->local_port = ntohs(local_addr.sin_port);
		_clean_recv_buf( con );
		_change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _negotiation_cb );
    } 

}


int start_client_process( socks_client_process_t *process)
{
	
	// create epoll    
	process->epoll_fd = epoll_create(MAX_EVENTS);    
	if(process->epoll_fd <= 0) {
		DEBUG_ERR( "[ %s:%d ] create epoll failed:%d, %m\n", __FILE__, __LINE__, errno, errno );  
		return -1;
	}

	int i=0;
	for( i=0; i< process->sockd_step; i++ ){
		_init_client_socket( process );
	}
	
	printf("client_num running: %s:%d, clients:%d\n", process->sockd_ip, process->sockd_port, process->client_num );  
	
	// event loop    
	struct epoll_event events[MAX_EVENTS];    
	
	int timer = 5000;    
	while(1){    
		// wait for events to happen 
		int fds = epoll_wait(process->epoll_fd, events, MAX_EVENTS, timer);    
		if(fds < 0){    
			printf("epoll_wait error, exit\n");    
			break;    
		}
		
		for( i = 0; i < fds; i++){
			if(events[i].events&(EPOLLIN|EPOLLOUT) )    
			{    
				socks_client_connection_t *con = (socks_client_connection_t*)events[i].data.ptr; 
				if( !con )
					continue;
				con->call_back( process, con->fd, events[i].events, con );  
			}
			else if((events[i].events&(EPOLLERR|EPOLLHUP) ))     
			{    
				socks_client_connection_t *con = (socks_client_connection_t*)events[i].data.ptr;  
				if( !con )
					continue;
				DEBUG_ERR( "[ %s:%d ] epoll error events: %d, fd:%d", __FILE__, __LINE__, events[i].events, con->fd );
				_close_conenect( process, con, 1);
			} 
		}
/*
		DEBUG_INFO( "file_len:%d, max_clients:%d, closed_num:%d, client_num:%d, max_cost_ms:%d, min_cost_ms:%d, avg_cost_ms:%d, succcess:%d, fail:%d ", 
			process->file_len, process->max_clients, process->closed_num, process->client_num, process->max_cost_ms, 
			process->min_cost_ms, process->success_num>0?(process->success_cost_ms/process->success_num):0,
			process->success_num, process->fail_num );
*/
		for( i=0; i< process->closed_num; i++ ){
			free( process->closed_connection[i] );
		}
		process->closed_num = 0;
		
		long now = get_current_ms();
		if( process->last_connect_stamp + process->connect_interval > now )
			continue;
		
		process->last_connect_stamp = now;
		int to_init = process->max_clients-process->client_num;
		if( to_init> process->sockd_step)
			to_init = process->sockd_step;

		for( i=0; i< to_init; i++ ){
			if( _init_client_socket( process )<0 )
				break;
		}
		
	}
	return 0;

}

int main( int argc, char *argv[] )
{
	/*
	struct timeb tb;
	struct timeval tv;
	struct timezone tz;

	if( ftime(&tb) )
		return -1;

	printf("tb now:s:%ld, ms:%d, tz:%d, f:%d, delta:%d\n", tb.time, tb.millitm, tb.timezone, tb.dstflag, (tb.time % (24*3600))/3600 );

	if( gettimeofday(&tv, &tz) )
		return -1;
	
	printf("tv now:s:%ld, us:%d, tz:%d, f:%d\n", tv.tv_sec, tv.tv_usec, tz.tz_minuteswest, tz.tz_dsttime );
	
	long now = tb.time;
	long stamp = now - (now % (24*3600))-8*3600;
	struct tm *ptime = localtime(&tb.time);
	char tmp[64];
	memset(tmp, 0, sizeof(tmp));
	if (strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", ptime)) {
		printf("now:%s\n", tmp);
	}

	memset(tmp, 0, sizeof(tmp));
	ptime = localtime(&stamp);
	if (strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", ptime)) {
		printf("stamp:%s\n", tmp);
	}
	*/

	// init client process info

	socks_client_process_t process;
	memset( &process, 0, sizeof( process ) );
	
	process.cmd			= 3;
	process.max_clients = 4000;
	process.min_cost_ms = 999999999;
	
	process.sockd_ip	= "192.168.179.130";
	process.sockd_port	= 8989; 
	process.sockd_step	= 20;
	process.last_connect_stamp = get_current_ms();
	process.connect_interval = 5*1000;	// 5s
	
	process.remote_ip	= "192.168.179.130";
	process.remote_port	= 8082; 
	
	process.local_ip		= "192.168.179.130";
	process.local_udp_port	= 2233;					// for udp test
	
	process.token		= "003";					// for meteor test
	process.app 		= "com.tencent.mobileqq";	// for meteor test
	process.orderkey	= "123456";					// for meteor test
	
	process.user		= "root";					// for dante test
	process.passwd		= "123456";					// for dante test

	// 612  	index.html
	// 10146	001.jpg
	// 51060	50.log
	process.file_len	= 11518017;					// for tcp test
	process.file_name	= "003.jpg";				// for tcp test

	//liul
	process.udpdata="udp test!!!";
	/*
	char file_path[FILE_PATH_LENGTH];
	getcwd(file_path, FILE_PATH_LENGTH);
	char epoll_test_result_file[FILE_PATH_LENGTH];
	sprintf(epoll_test_result_file,"%s/logs/epoll_result.txt", file_path);
	process.save_file=fopen(epoll_test_result_file,"wb");*/

	
	char * usage =	"usage: client [-h] [-c max_clients file_len file_name sockd_step\n" 		                "connect_interval]\n"
					"   options:\n"
					"     -h print the help info\n"
					"     -c conf for max_clients file_len file_name\n";
	if( argc==2){
		if( strcmp(argv[1], "-h" )==0 ){
			printf( usage );
			exit(0);
		}
	}
	if( argc>2){
		if( strcmp(argv[1], "-c" )!=0 ){
			printf( usage );
			exit(0);
		}
		if( argc >= 3)
			process.max_clients = atoi(argv[2]);
		if( argc >= 4)
			process.file_len = atoi(argv[3]);
		if( argc >= 5)
			process.file_name = argv[4];
		if( argc >= 6)
			process.sockd_step = atoi(argv[5]);
		if( argc >= 7)
			process.connect_interval = atoi(argv[6]);
	}

	return start_client_process(&process);
}

 

