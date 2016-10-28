
#include "sockd.h"
#include "meteor.h"
#include "meteor_process.h"

pid_t    g_pid;
int      process_slot;
int      last_process;

unsigned int	process;
int				daemonized;

sig_atomic_t  sig_sigio;
sig_atomic_t  sig_sigalrm;

sig_atomic_t  to_reap;
sig_atomic_t  to_terminate;
sig_atomic_t  to_noaccept;
sig_atomic_t  to_quit;
sig_atomic_t  to_reload;

unsigned int	status_exiting;
unsigned int	status_noaccepting;
unsigned int	status_restart;

extern socks_module_config_t g_config;
extern int process_type;

socks_signal_t  signals[] = {
    { SIGSYS,  "SIGSYS", "", print_stack_of_signal },
    { SIGPIPE, "SIGPIPE", "", print_stack_of_signal },
    { SIGHUP,  "SIGHUP", "reload", signal_handler },    
	{ SIGHUP,  "SIGHUP", "reload", signal_handler },	
    { SIGQUIT, "SIGQUIT", "quit", signal_handler },        /* slowly */
    { SIGTERM, "SIGTERM", "stop", signal_handler },        /* fast   */
    { SIGCHLD, "SIGCHLD", "sigchld", signal_handler },
    { 0, NULL, "", NULL }
};

process_signal_status_t processes[MAX_PROCESS_NUM];

pid_t spawn_process( int worker, int respawn)
{
    pid_t  pid;
    int  s;
    
	if (respawn >= 0) {
		s = respawn;
	}
	else {
		for (s = 0; s < last_process; s++) {
			if (processes[s].pid == -1) {
				break;
			}
		}

		if (s == MAX_PROCESS_NUM) { 	 
			return INVALID_PID;
		}
	}

    process_slot = s;
    pid = fork();
    switch (pid) {
	    case -1:
			sys_log( LL_ERROR, "fork() failed while spawning worker process, port:%d, %s", 
				g_config.worker_config[worker].listen_port, strerror(errno) );
	        return INVALID_PID;

	    case 0:
			pid = getpid();
	        start_worker_process( &g_config.worker_config[worker] );
	        break;

	    default:
	        break;
    }

	sys_log( LL_NOTICE, "started worker process [pid:%d], port:%d", pid, g_config.worker_config[worker].listen_port );

    processes[s].pid = pid;
    processes[s].status_exited= 0;

    if (respawn >= 0) {
        return pid;
    }

    processes[s].worker = worker;
	if( strlen( g_config.worker_config[worker].worker_name ) >0 )
	   	sprintf( processes[s].name, "%s-%d", g_config.worker_config[worker].worker_name, 
			g_config.worker_config[worker].listen_port );
	else
		sprintf( processes[s].name, "%s-%d", "worker", g_config.worker_config[worker].listen_port );

   	processes[s].status_exiting= 0;
   
    switch (respawn) {
    case PROCESS_RESPAWN:
        processes[s].status_just_spawn = 0;
        break;

    case PROCESS_JUST_RESPAWN:
        processes[s].status_just_spawn = 1;
        break;
    }

    if (s == last_process) {
        last_process++;
    }
    return pid;
}

void wait_child_process_get_status(void)
{
    int              status;
    char            *process;
    pid_t            pid;
    int              err;
    int              i;
    int              one;

    one = 0;
    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = errno;

            if (err == EINTR) {
                continue;
            }

            if (err == ECHILD && one) {
                return;
            }

            if (err == ECHILD) {
                sys_log( LL_ERROR, "ECHILD, waitpid() failed. %s\n", strerror(err) );
                return;
            }

            sys_log( LL_ERROR, "waitpid() failed. %d:%s\n", err, strerror(err) );
            return;
        }


        one = 1;
        process = "unknown process";
        for (i = 0; i < last_process; i++) {
            if (processes[i].pid == pid) {
                processes[i].status = status;
                processes[i].status_exited = 1;
                process = processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
			sys_log( LL_WARNING, "%s %d exited on signal %d", process, pid, WTERMSIG(status));
        } 
		else {
			sys_log( LL_WARNING, "%s %d exited with code %d", process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && processes[i].to_respawn) {  
			sys_log( LL_WARNING, "%s %d exited with fatal code %d, cannot be respawned", process, pid, WEXITSTATUS(status));
            processes[i].to_respawn = 0;
        }
    }
}

int reap_children()
{
    int n, i;
    int live = 0;

    for (i = 0; i < last_process; i++) {
        if (processes[i].pid == -1) {
            continue;
        }

        if (processes[i].status_exited) {
            
            if (processes[i].to_respawn && !processes[i].status_exiting && !to_terminate && !to_quit ) {
                if (spawn_process( processes[i].worker, i ) == INVALID_PID) {
					sys_log( LL_WARNING, "could not respawn %s", processes[i].name );
					continue;
                }

                live = 1;
                continue;
            }
            
            if (i == last_process - 1) {
                last_process--;

            }
			else {
                processes[i].pid = -1;
            }

        } 
		else if (processes[i].status_exiting ) {
            live = 1;
        }
    }

    return live;
}


void print_stack_of_signal( int signo )
{
    char _signal[64][32] = {
        "1: SIGHUP", "2: SIGINT", "3: SIGQUIT", "4: SIGILL",
        "5: SIGTRAP", "6: SIGABRT", "7: SIGBUS", "8: SIGFPE",
        "9: SIGKILL", "10: SIGUSR1", "11: SIGSEGV", "12: SIGUSR2",
        "13: SIGPIPE", "14: SIGALRM", "15: SIGTERM", "16: SIGSTKFLT",
        "17: SIGCHLD", "18: SIGCONT", "19: SIGSTOP", "20: SIGTSTP",
        "21: SIGTTIN", "22: SIGTTOU", "23: SIGURG", "24: SIGXCPU",
        "25: SIGXFSZ", "26: SIGVTALRM", "27: SIGPROF", "28: SIGWINCH",
        "29: SIGIO", "30: SIGPWR", "31: SIGSYS", "34: SIGRTMIN",
        "35: SIGRTMIN+1", "36: SIGRTMIN+2", "37: SIGRTMIN+3", "38: SIGRTMIN+4",
        "39: SIGRTMIN+5", "40: SIGRTMIN+6", "41: SIGRTMIN+7", "42: SIGRTMIN+8",
        "43: SIGRTMIN+9", "44: SIGRTMIN+10", "45: SIGRTMIN+11", "46: SIGRTMIN+12",
        "47: SIGRTMIN+13", "48: SIGRTMIN+14", "49: SIGRTMIN+15", "50: SIGRTMAX-14",
        "51: SIGRTMAX-13", "52: SIGRTMAX-12", "53: SIGRTMAX-11", "54: SIGRTMAX-10",
        "55: SIGRTMAX-9", "56: SIGRTMAX-8", "57: SIGRTMAX-7", "58: SIGRTMAX-6",
        "59: SIGRTMAX-5", "60: SIGRTMAX-4", "61: SIGRTMAX-3", "62: SIGRTMAX-2",
        "63: SIGRTMAX-1", "64: SIGRTMAX" };

    if( signo >= 1 && signo <= 64)   
        sys_log(LL_ERROR, "[%s] stack frames:", _signal[signo-1]);
    else
        sys_log(LL_ERROR, "[unknown sig: %d] stack frames:", signo);
    func_stack_dump(0);

    if( SIGPIPE != signo && SIGSYS != signo )
        exit(-1);
}


int send_signal_to_master_process(char *name)
{
    pid_t         pid = -1;
   
    FILE *fpr = fopen( g_config.pid_file_name, "r");
    if( fpr != NULL ) {
        fscanf(fpr, "%d", &pid);
        fclose(fpr);
    }
    
    if (pid == -1) {
        return -1;
    }

    socks_signal_t  *sig;
    for (sig = signals; sig->signo != 0; sig++) {
        if (strcmp(name, sig->name) == 0) {
            printf( "send signal %s to master process\n", sig->signame);
            if(kill(pid, sig->signo) != -1) {
                return 0;
            }
        }
    }

    return -1;
}

void send_signal_to_worker_process(int signo) 
{
    //print_stack_of_signal(signo);
    int i = 0;

	socks_signal_t * sig;
	for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
    for( ; i< last_process; i++) {
		sys_log(LL_DEBUG, "child process: %d %d exiting:%d exited:%d respawn:%d just_respawn:%d",
            i, processes[i].pid, processes[i].status_exiting, processes[i].status_exited, 
            processes[i].to_respawn, processes[i].status_just_spawn );
		
        if (processes[i].pid == -1) {
            continue;
        }
        
        if (processes[i].status_exiting  && signo == SIGQUIT) {
            continue;
        }

        /*
		if (processes[i].status_just_spawn) {
            printf("new worker[%d]!!!\n", processes[i].pid);
            processes[i].status_just_spawn = 0;
            continue;
        }
        */
        //printf("master send sig[%d] to worker[%d]\n", signo, processes[i].pid);
        if (kill( processes[i].pid, signo ) == -1) {      
            int err = errno;
            sys_log( LL_WARNING, "kill(%d, %s) failed, %s", processes[i].pid, sig->signame, strerror(err) );
            if (err == ESRCH) {
                processes[i].status_exited = 1;
                processes[i].status_exiting = 0;
                to_reap = 1;
            }
            
            continue;
        }

		processes[i].status_exiting = 1;
		
    }
	
}


void  signal_handler(int signo)
{
    int err = errno;
	char *action = "";
	pid_t pid = getpid();
	
	socks_signal_t * sig;
	for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
    switch(process_type) {
    case PROCESS_SINGLE:
	case PROCESS_MASTER:
        switch (signo) {
	        case SIGQUIT:
				to_quit = 1;
           		action = "shutting down";
	            break;
				
	        case SIGTERM:
	            action = "exiting";
	            to_terminate = 1;
	            break;

	        case SIGHUP:
	            to_reload = 1;
				action = "reload config";
				break;
				
			case SIGALRM:
				 sig_sigalrm = 1;
				 break;
			
			case SIGIO:
				 sig_sigio = 1;
				 break;
				 
	        case SIGCHLD:
	            to_reap = 1;
	            break;
        }   
    	sys_log( LL_NOTICE, "master process [pid:%d] received signal #%d(%s). %s\n", pid, signo, sig->name, action );
        break;
		
    case PROCESS_WORKER:
        switch (signo) {
	        case SIGQUIT:
	            action = "shutting down";
	            to_quit = 1;
	            break;
				
	        case SIGTERM:
			case SIGINT:
	            action = "exiting";
	            to_terminate = 1;
	            break;
				
			case SIGHUP:
			case SIGIO:
				action = ", ignoring";
				break;
		}
    	sys_log( LL_NOTICE, "worker process [pid:%d] received signal #%d(%s). %s\n", pid, signo, sig->name, action );
        break;
    }
	
    if (signo == SIGCHLD) {
        wait_child_process_get_status();
    }
	errno = err;
}

void socks_init_signals()
{
    socks_signal_t     *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        memset(&sa, 0, sizeof(struct sigaction) );
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            sys_log(LL_ERROR, "[%s:%d] sigaction failed, sig:%s", __func__, __LINE__, sig->signame );
			return;
        }
    }
}

int meteor_daemon()
{
    int  fd;

    switch (fork()) {
    case -1:
        sys_log( LL_ERROR, "fork() failed. %s", strerror(errno) );
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }

    if (setsid() == -1) {
        sys_log( LL_ERROR, "setsid() failed. %s", strerror(errno) );
        return -1;
   }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        sys_log( LL_ERROR, "open(\"/dev/null\") failed. %s", strerror(errno) );
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        sys_log( LL_ERROR, "dup2(STDIN) failed. %s", strerror(errno) );
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        sys_log( LL_ERROR, "dup2(STDOUT) failed. %s", strerror(errno) );
        return -1;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
			sys_log( LL_ERROR, "close() failed. %s", strerror(errno) );
			return -1;
        }
    }

    return 0;
}



