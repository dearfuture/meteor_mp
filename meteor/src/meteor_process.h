
#include <signal.h>

#include "meteor.h"
#include "sockd.h"

#define PROCESS_SINGLE     0
#define PROCESS_MASTER     1
#define PROCESS_SIGNALLER  2
#define PROCESS_WORKER     3

#define PROCESS_NORESPAWN     -1
#define PROCESS_JUST_SPAWN    -2
#define PROCESS_RESPAWN       -3
#define PROCESS_JUST_RESPAWN  -4
#define PROCESS_DETACHED      -5

#define MAX_PROCESS_NUM		1024
#define INVALID_PID			-1

typedef struct socks_signal_s signal_t;
typedef struct process_signal_status_s process_signal_status_t;

struct socks_signal_s{
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
};

struct process_signal_status_s
{
    // linux process info and status
	pid_t pid;
	char name[WORKER_NAME_LEN];
	int worker;
	int status;
	
	unsigned int to_quit:1;
	unsigned int to_terminate:1;
	unsigned int to_noaccept:1;
	unsigned int to_respawn:1;
	
	unsigned int status_exiting:1;
	unsigned int status_exited:1;
	unsigned int status_just_spawn:1;
	
	unsigned int sig_child:1;
	unsigned int sig_noaccept:1;
	unsigned int sig_stop:1;
	unsigned int sig_quit:1;
	unsigned int sig_reload:1;
	
};

int send_signal_to_master_process(char *signame);
void send_signal_to_worker_process(int signo) ;

void  signal_handler(int signo);
void socks_init_signals();
void print_stack_of_signal( int no );

pid_t spawn_process(int worker, int respawn);

void wait_child_process_get_status(void);

int reap_children();
int meteor_daemon();


