
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#ifndef GET_TIME_H
#define GET_TIME_H

#define TIME_BUFFER_SIZE    40    /* buffer size of time_buffer */
char *GetTimeStr(char *time_buf);
#endif



extern int GetHttpreq(char * resourse,char *det_ip,char *http_file);//get http request
extern char* ReadConfig(const char* FileName, char *VariableName);  //read config
extern int SaveRecvData(char *recievedata,char * filepath);//save recievedata from server
extern unsigned char * IntToHex(int aa,unsigned char  * convert_result);//int convert to hex for port
extern int IpToChars(int *convert_ipresult,char * dert_ip,int len);//ip convert to array
extern int CharsToInt(char *char_array);//char to int
extern void SystemLog(char* buf,FILE * g_syslogfd);//putout log
extern long long Char2long(char bytes[]);//char to long
extern int Char2int(char bytes[]);
extern int GetHttpResponse(char *http_response);//get http file
extern int GetHttpFileLen(char *http_response);
extern char * Search_config_file(const char* FileName, char *VariableName);
