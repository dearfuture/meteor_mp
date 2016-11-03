#include "sockd_udp.h"

static int _chk_udp_header( unsigned char *data );
static int _create_udp_connection_ipv4(socks_worker_process_t *process, socks_udp_connection_t *udp_conn, int up_direct );
static int _get_udp_addr_pos(socks_udp_connection_t * con, struct sockaddr_in * addr, int up_direct);

unsigned char *_get_udp_header( unsigned char *data,  socks_udp_header_t *header)
{
	memset(header, 0, sizeof(*header));
	memcpy(&header->reserved, data, sizeof(header->reserved));
	data += sizeof(header->reserved);

	memcpy(&header->frag, data, sizeof(header->frag));
	data += sizeof(header->frag);

	return (unsigned char *)copy_buf_to_socks_host(&header->host, ( unsigned char *)data );
}

static int _chk_udp_header( unsigned char *data )
{
	if( data[0]!=0 || data[1]!=0 || data[2] !=0 )
		return -1;
	if( data[3] != SOCKS_ATYPE_IPV4 && data[3] != SOCKS_ATYPE_IPV6 && data[3] != SOCKS_ATYPE_DOMAIN )
		return -1;
	return 0;
}

unsigned char * _copy_udp_header_to_buf( socks_udp_header_t *header, unsigned char *buf)
{
    /* reserved */
	memcpy(buf, &header->reserved, sizeof(header->reserved));
	buf += sizeof(header->reserved);
	memcpy(buf, &header->frag, sizeof(header->frag));
	buf += sizeof(header->frag);

	return (unsigned char *)copy_socks_host_to_buf( &header->host, buf );
}

void _hold_and_wait_udp_data_cb( socks_worker_process_t *process, int fd, int events,  void *arg)
{
    socks_connection_t *con = (socks_connection_t *)arg;
	int len = _recv_data( con, RECV_BUF_SIZE-con->data_length);
	if( len > 0 )
	{
		do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
		sys_log(LL_DEBUG, "[ %s:%d ] client control connection received some data, fd:%d, len:%d", __FILE__, __LINE__, fd, len );
		_clean_recv_buf( con );
	}
	else if( len <0 || con->eof ) 
	{
		//net disconnected. close session
		sys_log(LL_ERROR, "[ %s:%d ] client control connection eof:%d, fd:%d", __FILE__, __LINE__, con->eof, fd );
		close_session( process, con->session);
		return;
	}
	else
	{
		sys_log(LL_DEBUG, "[ %s:%d ] client control connection, no data received , fd: %d", __FILE__, __LINE__, fd );
	}
}


void _send_udp_connect_result( socks_worker_process_t *process, socks_connection_t *con, 
	socks_udp_connection_t *udp_client, socks_command_reply_t *reply, int result )
{
	
	if( result == 0 ){ // 建立udp socket成功
		reply->status= SOCKS_CMD_SUCCESS;
		reply->host.atype = SOCKS_ATYPE_IPV4;
		
		// 应返回外网ip给客户端
		//inet_aton( udp_client->local_hostname, &reply->host.addr.ipv4);  
		memcpy( &reply->host.addr.ipv4, &process->config->outer_addr_cache, sizeof(struct in_addr) );  
		
	    reply->host.port = htons(udp_client->local_port);
		send_cmd_reply( process, con, reply );
		_clean_recv_buf( con );
		_change_session_event( process->epoll_fd, con, con->fd, EPOLLIN|EPOLLHUP|EPOLLERR, _hold_and_wait_udp_data_cb );
		return;
	}
	
	// send udp socket create failed msg to client
	if( result == ENETUNREACH ) // 101
		reply->status= SOCKS_CMD_ERR_NET;
	else if( result == ECONNREFUSED )	//111
		reply->status= SOCKS_CMD_ERR_REFUSE;
	else if( result == EHOSTUNREACH )
		reply->status= SOCKS_CMD_ERR_HOST;
	else
		reply->status= SOCKS_CMD_ERR_FAIL;
	reply->host.atype = SOCKS_ATYPE_IPV4;
	send_cmd_reply( process, con, reply );
	close_session( process, con->session);

}

void _do_command_udp_associate( socks_worker_process_t *process, socks_connection_t *con, 
	socks_command_t *cmd, socks_command_reply_t *reply )
{
	if(cmd->host.atype == SOCKS_ATYPE_IPV4){
		//socks_connection_t *udp_client = (socks_connection_t *)malloc(sizeof(socks_connection_t));
		socks_udp_connection_t * udp_client = (socks_udp_connection_t*)malloc(sizeof(socks_udp_connection_t));
		if( udp_client == NULL ){
			sys_log(LL_ERROR, "[ %s:%d ] malloc udp_client error,fd: %d", __FILE__, __LINE__, con->fd );
			reply->version = SOCKS_VERSION_5;
			reply->host.atype = SOCKS_ATYPE_IPV4;
			reply->status = SOCKS_CMD_ERR_FAIL;
			send_cmd_reply( process, con, reply );
			close_session( process, con->session);
			return;
		}
		memset( (void *)udp_client, 0,	sizeof(socks_udp_connection_t) );
		con->session->udp_client = udp_client;
		udp_client->session = con->session;

		// TODO: 考虑到手机端NAT问题，应该强制设为con->peer_host?
		size_t hosta_len = strlen(con->peer_hostname);
		memcpy( udp_client->peer_hostname, con->peer_hostname, hosta_len );
		udp_client->peer_hostname[hosta_len]= '\0';
		memcpy( &udp_client->peer_host, &con->peer_host, sizeof(socks_host_t) ); //fixme
		udp_client->peer_host.port = cmd->host.port;
/*		
		char * hosta = inet_ntoa( cmd->host.addr.ipv4 );
		if( strcmp( hosta, "0.0.0.0" ) == 0 ){ //默认地址是，将tcp controller的对端ip作为udp client的对端ip
			size_t hosta_len = strlen(con->peer_hostname);
			memcpy( udp_client->peer_hostname, con->peer_hostname, hosta_len );
			udp_client->peer_hostname[hosta_len]= '\0';
			memcpy( &udp_client->peer_host, &con->peer_host, sizeof(socks_host_t) ); //fixme
			udp_client->peer_host.port = cmd->host.port;
		}
		else{
			size_t hosta_len = strlen(hosta);
			memcpy( udp_client->peer_hostname, hosta, hosta_len );
			udp_client->peer_hostname[hosta_len]= '\0';
			memcpy( &udp_client->peer_host, &cmd->host, sizeof(socks_host_t) );//fixme
		}
*/	
		sys_log(LL_DEBUG, "[ %s:%d ] udp_associate command: %s:%d", __FILE__, __LINE__, udp_client->peer_hostname, ntohs(udp_client->peer_host.port));
		
		int ret = _create_udp_connection_ipv4( process, udp_client, 1 ); 
		
		_send_udp_connect_result( process, con, udp_client, reply, ret );
	}
	else
	{
		sys_log(LL_ERROR, "[ %s:%d ] atype: 0x%x unsupported,fd: %d", __FILE__, __LINE__, cmd->host.atype, con->fd );
		reply->version = SOCKS_VERSION_5;
		reply->host.atype = SOCKS_ATYPE_IPV4;
		reply->status = SOCKS_CMD_ERR_ATYPE;
		send_cmd_reply( process, con, reply );
		close_session( process, con->session);
		return;
	}

}


static int _create_udp_connection_ipv4(socks_worker_process_t *process, socks_udp_connection_t *udp_conn, int up_direct )
{

	int fd = udp_conn->fd = socket(AF_INET, SOCK_DGRAM, 0);

    if ( fd < 0) {
		sys_log(LL_ERROR, "[ %s:%d ] create %s udp error, fd:%d, %s:%d", __FILE__, __LINE__, up_direct?"client":"remote", fd, 
			udp_conn->peer_hostname, ntohs(udp_conn->peer_host.port) );
		return -1;
    }
	
    int flags = fcntl( fd, F_GETFL, 0);
    if (flags < 0) {
        sys_log(LL_ERROR, "[ %s:%d ] get %s socket flags errorfd:%d, %s:%d", __FILE__, __LINE__, up_direct?"client":"remote", fd, 
			udp_conn->peer_hostname, ntohs(udp_conn->peer_host.port) );
		return -1;
    }

    if (fcntl( fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        sys_log(LL_ERROR, "[ %s:%d ] set %s udp nonblock error,fd:%d, %s:%d", __FILE__, __LINE__, up_direct?"client":"remote", fd, 
			udp_conn->peer_hostname, ntohs(udp_conn->peer_host.port) );
		return -1;
    }
	
	int value = process->config->reuseaddr ==1?1:0;
	if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
	{
		sys_log(LL_ERROR, "[ %s:%d ] set %s udp SO_REUSEADDR fail, fd:%d", __FILE__, __LINE__, up_direct?"client":"remote", fd );
	}

	struct sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof (s_addr));
    s_addr.sin_family = AF_INET;
	inet_aton( udp_conn->session->client->local_hostname, &s_addr.sin_addr);  
	// TODO: 实现配置的UDP端口范围
    s_addr.sin_port = 0;
	if( bind( fd, (  struct sockaddr*)&s_addr, sizeof(s_addr)) == -1 ){
		sys_log(LL_ERROR, "[ %s:%d ] bind %s udp failed, peer:%s:%d,  fd=%d", __FILE__, __LINE__, up_direct?"client":"remote", 
			udp_conn->peer_hostname, ntohs(udp_conn->peer_host.port), fd); 
		return errno;
    }

	socklen_t len = sizeof(s_addr);
	getsockname( fd, (struct sockaddr*)&s_addr, &len);
	copy_sockaddr_to_hostname( &s_addr.sin_addr, &udp_conn->local_hostname[0] );
	udp_conn->local_port = ntohs(s_addr.sin_port);
	sys_log(LL_DEBUG, "[ %s:%d ] bind %s udp ok, local: %s:%d, fd:%d", __FILE__, __LINE__, up_direct?"client":"remote", udp_conn->local_hostname, udp_conn->local_port, fd); 

	udp_conn->session->stage = SOCKS_STAGE_UDP_DATA;
	_clean_udp_recv_buf( udp_conn );
	_register_session_event( process->epoll_fd, (socks_connection_t *)udp_conn, fd, EPOLLIN|EPOLLHUP|EPOLLERR, _udp_data_transform_cb );

 	return 0;
	
}


/* while data from client or remote host, then transform to the other peer
   对于meteor流量网关来说，为了节省udp端口资源, 接收客户端和远端服务器都用同一个udp端口，
   根据packet的来源ip区分是客户端还是远端的数据包, 另外与客户端交互的packet是按socks5协议
   追加了socks_udp_header的，需要校验格式
*/
void _udp_data_transform_cb( socks_worker_process_t *process, int fd, int events,  void *arg)
{
    socks_udp_connection_t *con = (socks_udp_connection_t *)arg;

	if( con->session->stage != SOCKS_STAGE_UDP_DATA ){
		sys_log(LL_ERROR, "[ %s:%d ] error udp stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, fd );
		close_session( process, con->session);
		return;
	}
	
	if( !(events & EPOLLIN)){
		return;
	}
	
	int up_direct =  0;
	struct sockaddr_in addr;  
	int addr_len = sizeof(struct sockaddr_in);
	_clean_udp_recv_buf (con); // 需要确认数据包是否1次性可以读完，应该是一次性的
	int len = recvfrom( fd, con->buf,RECV_BUF_SIZE-con->data_length, 0 , (struct sockaddr *)&addr ,&addr_len); 

	if( len <= 0 )	{  // recvfrom error
		sys_log(LL_ERROR, "[ %s:%d ] recv udp from: %s:%d error, fd:%d, len:%d", __FILE__, __LINE__, 
			con->peer_hostname, ntohs(con->peer_host.port), fd, len);
		return;
	}
	
	con->data_length += len;
	char * peer_hostname = inet_ntoa( addr.sin_addr );
	int peer_port = ntohs(addr.sin_port);
	sys_log(LL_DEBUG, "[ %s:%d ] recv udp from: %s:%d, fd:%d, len:%d", __FILE__, __LINE__, 
		peer_hostname, peer_port, fd, len);

	if( strcmp(con->session->udp_client->peer_hostname, peer_hostname )==0 ){
		up_direct = 1;
		// 考虑到手机端做了NAT转换,应用udp包的实际端口覆盖cmd中接收的地址端口
		con->session->udp_client->peer_host.port = addr.sin_port; 
	}
	else{
		if( _chk_udp_header(con->buf )==0 ){
			// 来源地址不是客户端，但数据包有udp header，疑似非法packet，忽略这类数据包，所以也无需统计流量
			sys_log(LL_ERROR, "[ %s:%d ] recv no-approved udp from: %s:%d error, fd:%d, len:%d", __FILE__, __LINE__, 
				con->peer_hostname, peer_port, fd, len);
			return;
		}
	}
	
	if(up_direct){
		// stat up flow
		do_stat_order_flow( process, con->session, len+ETHERNET_IP_UDP_HEADER_SIZE, up_direct, 1 );
		if( _chk_udp_header(con->buf ) ){
			sys_log(LL_ERROR, "[ %s:%d ] recv udp from client: %s:%d, but no header, fd:%d, len:%d", __FILE__, __LINE__, 
				con->peer_hostname, peer_port, fd, len);
			return;
		}
		
		socks_udp_header_t header;
		unsigned char *real_data = _get_udp_header( &con->buf[0], &header );
		if(header.host.atype == SOCKS_ATYPE_IPV4){
			int send_length = con->data_length -(real_data - &con->buf[0]);
			convert_to_sockaddr_in( &header.host, &addr);
			
			int pos = _get_udp_addr_pos(con, &addr, up_direct);
			if( pos != -1 ){
				con->remote_up_byte_num[pos] += len+ETHERNET_IP_UDP_HEADER_SIZE;
			}
			
			addr_len = sizeof(addr);
			len = sendto( fd, real_data, send_length, 0, (struct sockaddr *)&addr, addr_len);  
			if( len< 0 ){
				sys_log(LL_ERROR, "[ %s:%d ] forward client udp error, to: %s:%d, fd:%d", __FILE__, __LINE__, 
					inet_ntoa(header.host.addr.ipv4), ntohs(header.host.port), fd );
			}
		}
		else{
			sys_log(LL_ERROR, "[ %s:%d ] atype unsupported, not forward client udp to: %s:%d, fd: %d", __FILE__, __LINE__, 
				inet_ntoa(header.host.addr.ipv4), ntohs(header.host.port), fd );
		}
	}
	else{ // remote

		unsigned char buf[RECV_BUF_SIZE];
		memset(buf, 0, sizeof(buf) );
		
		socks_udp_header_t header;
		memset(&header, 0, sizeof(header) );
		convert_to_socks_host_t( &header.host, &addr );
		
		unsigned char * data = _copy_udp_header_to_buf( &header, buf );
		
		//copy remote received data to client's buffer
		size_t head_length = data-buf;
		int cpy_length = sizeof(buf)-head_length;
		if( cpy_length >  con->data_length )
			cpy_length = con->data_length;
		memcpy( data, &con->buf[0], cpy_length ); 
		
		int send_length = head_length+cpy_length;
		convert_to_sockaddr_in( &con->peer_host, &addr);
		
		int pos = _get_udp_addr_pos(con, &addr, up_direct);
		if( pos != -1 ){
			con->remote_down_byte_num[pos] += (len+ETHERNET_IP_UDP_HEADER_SIZE);
		}

		addr_len = sizeof(addr);
		len = sendto( fd, buf, send_length, 0, (struct sockaddr *)&addr, addr_len );
		if( len< 0 ){
			sys_log(LL_ERROR, "[ %s:%d ] forward remote udp error: %s:%d, fd: %d", __FILE__, __LINE__,
				con->peer_hostname, ntohs(con->peer_host.port), fd );
		}
		else{
			// stat down flow
			do_stat_order_flow( process, con->session, len+ETHERNET_IP_UDP_HEADER_SIZE, up_direct, 1 );
		}
		return;
	}
	

}

static int _get_udp_addr_pos(socks_udp_connection_t * con, struct sockaddr_in * addr, int up_direct)
{
	int i = 0;
	while( i < con->udp_remote_num ){
		if(memcmp(&(con->remote_addr[i]), addr, sizeof(struct sockaddr_in)) == 0)
			return i;
		i++;
	}
	if (up_direct){
		if ( con->udp_remote_num < SESSION_UDP_REMOTE_NUM ){
			memcpy(&con->remote_addr[i], addr, sizeof(struct sockaddr_in) ) ;
			con->udp_remote_num++;
			return i;
		}
	}

	return -1;
}

#if 0
// upd_client 和 remote是独立端口, 在多网卡及内外网卡情况下可以考虑使用(代码暂时保留)
void _udp_data_transform_cb_2( socks_worker_process_t *process, int fd, int events,  void *arg)
{
    socks_connection_t *con = (socks_connection_t *)arg;

	if( con->session->stage != SOCKS_STAGE_UDP_DATA ){
		sys_log(LL_ERROR, "[ %s:%d ] error udp stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, fd );
		close_session( process, con->session);
		return;
	}
	
	int up_direct =  0;
	if( fd == con->session->udp_client->fd )
		up_direct = 1;

	if( events & EPOLLIN)
	{
		struct sockaddr_in addr;  
    	int addr_len = sizeof(struct sockaddr_in);
		_clean_udp_recv_buf (con); // 需要确认数据包是否1次性可以读完，应该是一次性的
		int len = recvfrom( fd, con->buf,RECV_BUF_SIZE-con->data_length, 0 , (struct sockaddr *)&addr ,&addr_len); 

		if( len <= 0 )
		{ //recvfrom error
			sys_log(LL_ERROR, "[ %s:%d ] recv udp from: %s:%d error, fd:%d, len:%d", __FILE__, __LINE__, con->peer_hostname, ntohs(con->peer_host.port), fd, len);
			return;
		}
		
		if(up_direct){
			// stat up flow
			do_stat_order_flow( process, con->session, len+ETHERNET_IP_UDP_HEADER_SIZE, up_direct, 1 );
		}
		
		socks_connection_t *peer = con->peer_conn;
		con->data_length += len;
		char *peer_hostname = inet_ntoa( addr.sin_addr);
		int peer_port = ntohs(addr.sin_port);
		sys_log(LL_DEBUG, "[ %s:%d ] recv udp from: %s:%d, fd:%d, len:%d", __FILE__, __LINE__, peer_hostname, peer_port, fd, len);
		
		if( addr.sin_port != con->peer_host.port || strcmp( peer_hostname, con->peer_hostname ) != 0 ){ 
			// 来源地址非法数据包，忽略这类数据包
			sys_log(LL_ERROR, "[ %s:%d ] recv no-approved udp from: %s:%d error, fd:%d, len:%d", __FILE__, __LINE__, con->peer_hostname, peer_port, fd, len);
			return;
		}
		
		if( up_direct ){
			if( _chk_udp_header(con->buf ) ){
				sys_log(LL_ERROR, "[ %s:%d ] recv udp from: %s:%d, but no header, fd:%d, len:%d", __FILE__, __LINE__, con->peer_hostname, peer_port, fd, len);
				return;
			}
			socks_udp_header_t header;
			unsigned char *real_data = _get_udp_header( &con->buf[0], &header );
			if( !peer ){
				// create remote peer connection
				if(header.host.atype == SOCKS_ATYPE_IPV4)
				{
					socks_connection_t *remote = (socks_connection_t *)malloc(sizeof(socks_connection_t));
					if( remote == NULL ){
						sys_log(LL_ERROR, "[ %s:%d ] malloc remote error,fd: %d", __FILE__, __LINE__, fd );
						close_session( process, con->session);
						return;
					}
					memset( (void *)remote, 0,	sizeof(socks_connection_t) );
					con->session->remote= remote;
					remote->session = con->session;
					remote->peer_conn = con;
					con->peer_conn = remote;
					peer = remote;
					
					memcpy( &remote->peer_host, &header.host, sizeof(header.host) );
					copy_sockaddr_to_hostname( &header.host.addr.ipv4, &remote->peer_hostname[0] );
					sys_log(LL_DEBUG, "[ %s:%d ] remote: %s:%d", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
					
					int ret = _create_udp_connection_ipv4( process, remote, 0 ); 
					if( ret < 0 ){
						sys_log(LL_ERROR, "[ %s:%d ] remote create fail: %s:%d, fd:%d", __FILE__, __LINE__, remote->peer_hostname, 
							ntohs(remote->peer_host.port), fd );
						close_session( process, remote->session);
						return;
					}
					
				}
				else
				{
					sys_log(LL_ERROR, "[ %s:%d ] remote atype: 0x%x unsupported,fd: %d", __FILE__, __LINE__, con->peer_host.atype, fd );
					close_session( process, con->session);
					return;
				}
			}
			
			int send_length = con->data_length -(real_data - &con->buf[0]);
			convert_to_sockaddr_in( &header.host, &addr);
			
			addr_len = sizeof(addr);
			len = sendto( peer->fd, real_data, send_length, 0, (struct sockaddr *)&addr, addr_len);  
			if( len< 0 ){
				sys_log(LL_ERROR, "[ %s:%d ] forward client udp error: %s:%d, fd: %d", __FILE__, __LINE__, peer->peer_hostname, ntohs(header.host.port), fd );
			}
			return;
		}
		else{ // remote
			if( !peer ){  // no udp_client, error
				sys_log(LL_ERROR, "[ %s:%d ] no udp_client, remote fd:%d", __FILE__, __LINE__, fd );
				close_session( process, con->session);
				return;
			}
			_clean_udp_recv_buf ( peer );
			
			socks_udp_header_t header;
			memset(&header, 0, sizeof(header) );
			convert_to_socks_host_t( &header.host, &addr );
			
			unsigned char * buf = _copy_udp_header_to_buf( &header, &peer->buf[0] );
			
			//copy remote received data to client's buffer
			size_t head_length = buf-&peer->buf[0];
			int cpy_length = sizeof(peer->buf[0])-head_length;
			if( cpy_length >  con->data_length )
				cpy_length = con->data_length;
			memcpy( buf, &con->buf[0], cpy_length ); 
			
			int send_length = head_length+cpy_length;
			convert_to_sockaddr_in( &peer->peer_host, &addr);
			addr_len = sizeof(addr);
			len = sendto( peer->fd, &peer->buf[0], send_length, 0, (struct sockaddr *)&addr, addr_len);
			if( len< 0 ){
				sys_log(LL_ERROR, "[ %s:%d ] forward remote udp error: %s:%d, fd: %d", __FILE__, __LINE__, peer->peer_hostname, ntohs(peer->peer_host.port), fd );
			}
			else{
				// stat down flow
				do_stat_order_flow( process, con->session, len+ETHERNET_IP_UDP_HEADER_SIZE, up_direct, 1 );
			}
			return;
		}
	}
	else if( events & EPOLLOUT )
	{
		socks_connection_t *peer = con->peer_conn;
		if( peer->data_length > peer->sent_length ){
			sys_log(LL_DEBUG, "[ %s:%d ] continue, send to %s , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, up_direct?"client":"remote", con->fd, peer->fd, 
				peer->data_length, peer->sent_length);
			//_send_data( con->peer_conn, con->fd );
		}
		return;
	}
}
#endif

