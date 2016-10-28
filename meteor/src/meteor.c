//     
// meteor server(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
//  
#include "meteor.h"
#include "sockd.h"
#include "meteor_conf.h"
#include "log.h"

#include "meteor_process.h"
#include "sockd_redis.h"

unsigned char g_config_path[128];

socks_module_config_t g_config;

static int daemonized;

static int master_pid_fd;
static u_char  master_process[] = "meteor:master process";

unsigned int show_help;
unsigned int show_version;
unsigned int show_config;
unsigned int test_config;
unsigned int test_config;

static char *config_file = NULL;
static char *g_signal = NULL;

static char **g_os_argv;
static char *g_os_argv_last;

int process_type;

extern sig_atomic_t  to_reap;
extern sig_atomic_t  to_terminate;
extern sig_atomic_t  to_noaccept;
extern sig_atomic_t  to_quit;
extern sig_atomic_t  to_reload;


void func_stack_dump(int err)
{
    void *stack_p[32];
    char **stack_info;

    int size = backtrace( stack_p, sizeof(stack_p));
    stack_info = (char **)backtrace_symbols( stack_p, size);
    if( stack_info == NULL )
        return;

    if( err )
        sys_log(LL_ERROR, "errno:%d:%s, %d stack frames:", err, strerror(err), size );
    int i = 0;
    for( ; i < size; i++)
        sys_log(LL_ERROR, "frame #%d:%s", i, stack_info[i]);

    free( stack_info);
    fflush(NULL);
}


// get current time, in ms
long get_current_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((long)tv.tv_sec)*1000+((long)tv.tv_usec)/1000;
}

time_t get_mid_night_second( time_t now)
{
    time_t delta = (now % SECONDS_OF_ONE_DAY );
    time_t ret = now - delta -SECONDS_OF_TIME_ZONE;
    if( delta >( SECONDS_OF_ONE_DAY - SECONDS_OF_TIME_ZONE ) )
        ret += SECONDS_OF_ONE_DAY;
    return ret;
}

char * get_local_ip()
{
    int sfd, intr;
    struct ifreq buf[16];
    struct ifconf ifc;
    sfd = socket (AF_INET, SOCK_DGRAM, 0); 
    if (sfd < 0)
        return "0.0.0.0";
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(sfd, SIOCGIFCONF, (char *)&ifc))
        return "0.0.0.0";
    intr = ifc.ifc_len / sizeof(struct ifreq);
    while (intr-- > 0 && ioctl(sfd, SIOCGIFADDR, (char *)&buf[intr]));
    close(sfd);
    return inet_ntoa(((struct sockaddr_in*)(&buf[intr].ifr_addr))-> sin_addr);
}


void set_default_module_conf( socks_module_config_t *conf )
{
    memset( (void *)conf, 0, sizeof(socks_module_config_t) );

    conf->workers               = 1;
    conf->worker_max_sessions   = 4096;

    conf->order_check_interval  = 5*1000;
    conf->activity_check_interval = 5*1000;
    conf->order_frozen_timeout  = 3*3600*1000;
    conf->order_idle_timeout    = 5*60*1000;
    conf->order_update_interval = 5*1000;
    conf->activity_update_interval = 5*1000;
    conf->session_idle_timeout  = 1*60*1000;
    conf->order_event_check_interval= 5*1000;

    conf->pool_defrag_interval  = 1*60*1000;
    conf->pool_defrag_size      = 100;

    conf->sys_log_rotate_interval = 24*60*60; // seconds
    conf->flow_log_rotate_interval = 60*60;
    conf->sys_log_level         = LL_NOTICE;
    conf->sys_log_mode          = LOG_MODE_FILE;

    strcpy( conf->pid_file_name, "../logs/meteor.pid" );
    strcpy( conf->sys_log_file_name, "../logs/sys.log" );
    strcpy( conf->flow_log_file_name, "../logs/flow.log" );

    conf->worker_stat_update_interval = 5;  //seconds
    conf->daemon_mode           = 1;

    //set_default_worker_conf( conf, &conf->worker_config[0] );
    strcpy( conf->redis_host, "172.18.12.246" );
    conf->redis_port = 6379;

    int i;
    for(i = 0;i < 8;i++)
    {
       set_default_worker_conf( conf, &conf->worker_config[i] );
       conf->worker_config[i].listen_port = 1080 + i;
    }

}


void set_default_worker_conf( socks_module_config_t *conf, socks_worker_config_t *w_conf)
{
    //memset( (void *)w_conf, 0, sizeof(socks_worker_config_t) );
    if( strlen( w_conf->listen_host)==0 ||strcmp( w_conf->listen_host, "0.0.0.0" )== 0 )
        strcpy( w_conf->listen_host, get_local_ip() ); 
    if( strlen( w_conf->outer_host)==0 ||strcmp( w_conf->outer_host, "0.0.0.0" )== 0 ){
        strcpy( w_conf->outer_host,  w_conf->listen_host );
        inet_aton( w_conf->outer_host, &w_conf->outer_addr_cache );
    }
    w_conf->listen_port     = 8001;
    w_conf->listen_backlog  = 4096;
    w_conf->max_sessions    = conf->worker_max_sessions;
    w_conf->reuseaddr       = 1;
}

u_char *meteor_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}

void meteor_set_process_title(char *title)
{
    u_char     *p;
    g_os_argv[1] = NULL;
    
    p = meteor_cpystrn((u_char *) g_os_argv[0], (u_char *) title, g_os_argv_last-g_os_argv[0]);
    int len = g_os_argv_last - (char *) p;
    if (len>0) {
        memset( p, ' ', len );
    }
}


static int get_options(int argc, char *const *argv)
{
    char  *p;
    int   i;
    
    for (i = 1; i < argc; i++) {

        p = (char *) argv[i];

        if (*p++ != '-') {
            fprintf(stderr, "invalid option: \"%s\"\n", argv[i]);
            return -1;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                show_version = 1;
                show_help = 1;
                break;

            case 'v':
                show_version = 1;
                break;
  
            case 'V':
                show_version = 1;
                show_config = 1;
              break;
  
            case 't':
                show_version = 1;
                test_config = 1;
                
                if (*p) {
                    config_file = p;
                    goto next;
                }

                if (argv[++i]) {
                    config_file = argv[i];
                    goto next;
                }
                
                break;
     
            case 'c':
                if (*p) {
                    strcpy(g_config_path, p);
                    goto next;
                }

                if (argv[++i]) {
                    strcpy(g_config_path, argv[i]);
                    goto next;
                }

                fprintf(stderr, "option \"-c\" requires file name\n");
                return -1;
        
            case 's':
                if (*p) {
                    g_signal = (char *) p;
                } 
                else if (argv[++i]) {
                    g_signal = argv[i];

                } 
                
                if (strcmp(g_signal, "stop") == 0 || strcmp(g_signal, "quit") == 0 || strcmp(g_signal, "reload") == 0){
                    process_type = PROCESS_SIGNALLER;
                    goto next;
                }
                
                fprintf(stderr,  "option \"-s\" requires [ reload | quit | stop ]\n");
                return -1;

            default:
                fprintf(stderr, "invalid option: \"%c\"\n", *(p - 1));
                return -1;
            }
        }
    
        next:
            continue;
    }

    return 0;
}

static void write_and_lock_master_pid_file()
{
    if( master_pid_fd = open( g_config.pid_file_name, O_WRONLY|O_CREAT|O_TRUNC, 0644 )<0 ){
        sys_log( LL_ERROR, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        fprintf( stderr, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        exit(-1);
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl( master_pid_fd, F_SETLK, &lock) < 0){
        sys_log( LL_ERROR, "\nMeteor is running already.\n" );
        fprintf( stderr, "\nMeteor is running already.\n" );
        close( master_pid_fd );
        exit(-1);
    }
/*
    if( master_pid_fd = open( g_config.pid_file_name, O_WRONLY|O_CREAT|O_TRUNC, 0644)<0 ){
        sys_log( LL_ERROR, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        fprintf( stderr, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        exit(-1);
    }


    char buf[16];
    sprintf ( buf, "%d", getpid() );
    int pidsize = strlen(buf);
    if( write( master_pid_fd, buf, pidsize) != pidsize ){
        sys_log( LL_ERROR, "\n write pid[%s] to %s failed.\n", buf, g_config.pid_file_name );
        fprintf( stderr, "\n write pid[%s] to %s failed.\n", buf, g_config.pid_file_name );
        exit(-1);
    }  
    close( master_pid_fd );
*/
    FILE *fp = fopen( g_config.pid_file_name, "w");
    if( fp == NULL ) {
        sys_log( LL_ERROR, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        fprintf( stderr, "\ncan't open pid file:%s.\n", g_config.pid_file_name );
        exit(-1);
    }
    
    pid_t pid = getpid();
    if( fprintf(fp, "%d", pid )<0 ){
        sys_log( LL_ERROR, "\n write pid[%d] to %s failed.\n", pid, g_config.pid_file_name );
        fprintf( stderr, "\n write pid[%d] to %s failed.\n", pid, g_config.pid_file_name );
        fclose(fp);
        exit(-1);
    }
    fclose(fp);

}

static void master_process_exit( int code)
{
   sys_log( LL_NOTICE, "meteor master exited(%d)." , code );
   unlink( g_config.pid_file_name );
   log_exit();
   exit(code);
}


int main(int argc, char **argv)    
{    
    char *usage = "Usage: meteor [-?hvt] [-s signal] [-c filename] " "\x0a" "\x0a"
            "Options:" "\x0a"
            "  -?,-h         : this help" "\x0a"
            "  -v            : show version and exit" "\x0a"
            "  -V            : show version and config info, then exit" "\x0a"
            "  -t [filename] : test configuration and exit" "\x0a"
            "  -s signal     : send signal to a master process: "
                               "stop, quit, reload" "\x0a"
            "  -c filename   : set configuration file (default: ../conf/meteor.conf)" "\x0a" "\x0a";

    if( get_options(argc, argv)< 0 ){
        fprintf( stderr, "%s\n", usage );
        exit(0);
    }
    
    if( show_version ){
        fprintf( stderr, "meteor version: %s - mobile flow accounting gateway. copyright (c) 21cn.com 2013-2020.\n", METEOR_VER );
    }
    
    if( show_help ){
        fprintf( stderr, "\n%s\n", usage );
    }

    if( show_config ){
        strcpy( g_config_path, "../conf/meteor.conf" );
        fprintf( stderr, "\nconfig file: %s\n", g_config_path );
        
        set_default_module_conf( &g_config );
        if( read_config(g_config_path, &g_config) < 0 ){
            fprintf( stderr, "\nread config file failed: %s, %s\n", g_config_path, strerror(errno) );
            exit(-1);
        }
        print_config( &g_config );
    }

    if( test_config ){
        if( config_file == NULL )
            config_file = "../conf/meteor.conf";
        fprintf( stderr, "\ntesting config file: %s\n", config_file );
        
        set_default_module_conf( &g_config );
        if( read_config( config_file, &g_config) < 0 ){
            fprintf( stderr, "\nread config file failed: %s, %s\n", config_file, strerror(errno) );
            exit(-1);
        }
        else{
            fprintf( stderr, "\nconfig file syntax is ok.\n" );
            if( check_config( &g_config ) == 0 )
                fprintf( stderr, "\nconfig file test is successful.\n" );
        }
    }

    if( show_version || show_help || show_config || test_config )
        exit(0);


    set_default_module_conf( &g_config );
    
    if( strlen( g_config_path ) == 0 )
        strcpy( g_config_path, "../conf/meteor.conf" );

    if( read_config( g_config_path, &g_config) < 0 ){
        fprintf( stderr, "\nread config file failed: %s, %s\n", g_config_path, strerror(errno) );
        exit(-1);
    }

    if( check_config( &g_config ) < 0 ){
        fprintf( stderr, "\nconfig file check failed: %s\n", g_config_path );
        exit(-1);
    }

    if( process_type == PROCESS_SIGNALLER) {
        exit( send_signal_to_master_process(g_signal) );
    }

    log_init(0);

    socks_init_signals();

    if (g_config.daemon_mode) {
        if (meteor_daemon() != 0 ) {
            return 1;
        }
        daemonized = 1;
    }
    
    redisContext *redis_connect = redis_init();
    if( redis_connect == NULL ) {
        sys_log( LL_ERROR, "redis server %s:%d connect failed.", g_config.redis_host, g_config.redis_port );
        master_process_exit(-1);
    }
    redisFree(redis_connect);

    // start master process
    process_type = PROCESS_MASTER;

    write_and_lock_master_pid_file();

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);    // reload
    sigaddset(&set, SIGWINCH);  // noaccept
    sigaddset(&set, SIGQUIT);   // shutdown
    sigaddset(&set, SIGTERM);   // terminate
   
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        sys_log( LL_ERROR, "sigprocmask error\n");
        master_process_exit(-1);
    }
    sigemptyset(&set);

    // set master process title
    u_char *title, *p;
    int i;
    int size = sizeof(master_process);
    
    for (i = 0; i < argc; i++) {
        size += strlen(argv[i]) + 1;
    }
    
    g_os_argv = argv;
    g_os_argv_last = g_os_argv[0];
    for (i = 0; g_os_argv[i]; i++) {
        if (g_os_argv_last == g_os_argv[i]) {
            g_os_argv_last = g_os_argv[i] + strlen(g_os_argv[i]) + 1;
        }
    }
    g_os_argv_last--;

    title = (char *)malloc(size);
    if (title == NULL) {
        master_process_exit(-2);
    }

    int len = strlen(master_process);
    memcpy( title, master_process, len);
    p = title+len;
    for (i = 0; i < argc; i++) {
        *p++ = ' ';
        p = meteor_cpystrn(p, (u_char *) argv[i], size);
    }
    meteor_set_process_title(title);
    
    sys_log( LL_NOTICE, "start worker processes");
    for (i = 0; i < g_config.workers ; i++) {
        spawn_process( i, PROCESS_RESPAWN );
    }

    int live = 1;

    while(1)
    {
        sigsuspend(&set);
 
        if (to_reap) {
            to_reap = 0;
            sys_log( LL_NOTICE, "reap children" );
            live = reap_children();
        }

        if (!live && (to_terminate || to_quit)) {
            sys_log( LL_NOTICE, "master process exit(0)");
            master_process_exit(0);
        }

        if (to_terminate) {
            //send_signal_to_worker_process(SIGKILL);
            sys_log( LL_NOTICE, "terminate worker process");
            send_signal_to_worker_process(SIGTERM);
            //to_terminate = 0;
            continue;
        }    

        if (to_quit) {
            sys_log( LL_NOTICE, "gracefully quit worker process");
            send_signal_to_worker_process(SIGQUIT);
            continue;
        }
        
        if (to_reload) {
            //to_reload = 0;
            sys_log( LL_NOTICE, "reload configure and restart");
            
            if(live) send_signal_to_worker_process( SIGQUIT );
            usleep(2000*1000); // allow new processes to start, sleep 2000ms 
            if(live) 
            {
                to_reap = 1;
                continue;
            }
            to_reload = 0;
            socks_module_config_t conf;
            set_default_module_conf( &conf );
            if( read_config( g_config_path, &conf) < 0 ){
                sys_log( LL_WARNING, "reload config failed. file syntax may be wrong." );
                continue;
            }
            if( check_config( &conf ) < 0 ){
                sys_log( LL_WARNING, "check config failed. some values may be wrong." );
                continue;
            }
            memcpy( (void *)&g_config, (void*)&conf, sizeof(socks_module_config_t) );

            for (i = 0; i < g_config.workers ; i++) {
                spawn_process( i, PROCESS_JUST_RESPAWN );
            }

            live = 1;
        }
         
    }

    master_process_exit(0); 
}    


