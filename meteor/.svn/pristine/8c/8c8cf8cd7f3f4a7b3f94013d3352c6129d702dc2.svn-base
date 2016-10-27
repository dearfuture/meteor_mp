
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
//# define LINE_DIM 100;

int CharsToInt(char *char_array)//char to int
{
    int result=0;
    int i=0;
    while(char_array[i]!='\0')
    {
        result=result*10+char_array[i++]-48;
    }
    return result;
}

int SaveRecvData(char *recievedata,char * filepath)
{   FILE *fp;
    int i=0;
    fp=fopen(filepath,"wb");
    while(recievedata[i]!='\0' )
    {   
        fprintf(fp,"%c",recievedata[i]);
        i++;
    };
    fclose(fp);
    printf("write over!");
    return 0;
}
//convert to hexadecimal ?

unsigned char * IntToHex(int aa,unsigned char * convert_result)
{
    char buffer[4];
    sprintf(buffer, "%x", aa);
    //printf("%s\n", buffer);
    int i=0,j=0;
    int tempint[4];
    int byte_temp=0;
    while(buffer[i]!='\0')
    {
        if(buffer[i]>=48 && buffer[i]<=57)
        {
            byte_temp=(buffer[i++]-48)+byte_temp*16;
        }
        else if(buffer[i]>=97 && buffer[i]<=102)
        {
            byte_temp=(buffer[i++]-87)+byte_temp*16;
        }
        else if(buffer[i]>=64 && buffer[i]<=69)
        {
            byte_temp=(buffer[i++]-54)+byte_temp*16;
        }
    }
    if(convert_result==NULL)
        return NULL;
    convert_result[0]=byte_temp/256;
    convert_result[1]=byte_temp-256*convert_result[0];
    return (convert_result);
}//end int_to_hex

//convert ip to char[]

int IpToChars(int *convert_ipresult,char * dert_ip,int len)
{
    int i=0;
    int j=0;
    if(dert_ip==NULL)
    {
        printf("ip is null!!");
        return 0;
    }
    if(convert_ipresult==NULL)
    {
        printf("recieve data  is null!!");
        return 0;
    }
    while(dert_ip[i]!='\0'&&i<len)
    {
        int temp_ip=0;
        while(dert_ip[i]!='.'&&dert_ip[i]!='\0')
        {
            temp_ip=dert_ip[i++]-48+temp_ip*10;
        }
        convert_ipresult[j++]=temp_ip;
        i++;
    }
    return 1;
}//end ip_to_chars

//read config from files

char * Search_config_file(const char* FileName, char *VariableName)
{
    int LINE_DIM=100;  
    char *Str=(char*)malloc(sizeof(char)*100);
    char *VarName, *Comment=NULL, *Equal=NULL;  
    char *FirstQuote, *LastQuote, *P1, *P2;  
    int Line=0, Len=0, Pos=0;  
    FILE *file=fopen(FileName, "r");  
    if (file==NULL) {  
        fprintf(stderr, "Error: Could not find file %s/n/n", FileName);  
        exit(1);  
    }  
    while (fgets(Str, LINE_DIM-1, file) != NULL) {  
        Line++;  
        Len=strlen(Str);  
        if (Len==0) goto Next;  
        if (Str[Len-1]=='\n' || Str[Len-1]=='\r') Str[--Len]='\0';  
        Equal = strchr (Str, '=');          // search for equal sign  
        Pos = strcspn (Str, ";#!");         // search for comment  
        Comment = (Pos==Len) ? NULL : Str+Pos;  
        if (Equal==NULL || ( Comment!=NULL && Comment<=Equal)) goto Next;   // Only comment  
        *Equal++ = '\0';  
        if (Comment!=NULL) *Comment='\0';  
  
        // String  
        FirstQuote=strchr (Equal, '"');     // search for double quote char  
        LastQuote=strrchr (Equal, '"');  
        if (FirstQuote!=NULL) {  
            if (LastQuote==NULL) {  
                fprintf(stderr, "Error reading parameter file %s line %d - Missing end quote./n", FileName, Line);  
                goto Next;  
            }  
            *FirstQuote=*LastQuote='\0';  
            Equal=FirstQuote+1;  
        }  
          
        // removes leading/trailing spaces  
        Pos=strspn (Str, "\t");  
        if (Pos==strlen(Str)) {  
            fprintf(stderr, "Error reading parameter file %s line %d - Missing variable name./n", FileName, Line);  
            goto Next;      // No function name  
        }  
        while (((P1=strrchr(Str, ' '))!=NULL) || ((P2=strrchr(Str, '\t'))!=NULL))  
            if (P1!=NULL) *P1='\0';  
            else if (P2!=NULL) *P2='\0';  
        VarName=Str+Pos;  
        //while (strspn(VarName, " /t")==strlen(VarName)) VarName++;  
  
        Pos=strspn (Equal, " \t");  
        if (Pos==strlen(Equal)) {  
            fprintf(stderr, "Error reading parameter file %s line %d - Missing value./n", FileName, Line);  
            goto Next;      // No function name  
        }  
        Equal+=Pos;  
  
        if (strcmp(VarName, VariableName)==0) {     // Found it  
            fclose(file);  
            return Equal;  
        }  
        Next:;  
    }  
      
    fclose(file);  
    return NULL;  
}
//gettime
char *GetTimeStr(char *time_buf)
{
    time_t    now_sec;
    struct tm    *time_now;
    if(    time(&now_sec) == -1)
    {
        perror("time() in get_time.c");
        return NULL;
    }
    if((time_now = localtime(&now_sec)) == NULL)
    {
        perror("localtime in get_time.c");
        return NULL;
    }
    char *str_ptr = NULL;
    if((str_ptr = asctime(time_now)) == NULL)
    {
        perror("asctime in get_time.c");
        return NULL;
    }
    bzero(time_buf,sizeof(time_buf));
    strcat(time_buf, str_ptr);
    return time_buf;
}
//putout log
void SystemLog(char* buf,FILE * g_syslogfd)
{
   char time_log_buf[100];
   sprintf(time_log_buf,"%s %s: \n",__DATE__,__TIME__);
   fwrite(time_log_buf,strlen(time_log_buf),1,g_syslogfd);
   fwrite(buf,strlen(buf),1,g_syslogfd);
   fflush(g_syslogfd);
   //printf("writing......\n");
}

long long Char2long(char bytes[]) {
   long long n = 0;
  n =  ((bytes[0] << 56) & 0xFF00000000000000U)
     + ((bytes[1] << 48) & 0x00FF000000000000U)
     + ((bytes[2] << 40) & 0x0000FF0000000000U)
     + ((bytes[3] << 32) & 0x000000FF00000000U)
     + ((bytes[4] << 24) & 0x00000000FF000000U)
     + ((bytes[5] << 16) & 0x0000000000FF0000U)
     + ((bytes[6] << 8)  & 0x000000000000FF00U)
     + (bytes[7]         & 0x00000000000000FFU);
  return n;
}

int Char2int(char bytes[]) {
   int n = 0;
  n =   ((bytes[0] << 24) & 0xFF000000U)
     + ((bytes[1] << 16) & 0x00FF0000U)
     + ((bytes[2] << 8)  & 0x0000FF00U)
     + (bytes[3]         & 0x000000FFU);
  return n;
}

int GetHttpreq(char * resourse,char *det_ip,char *http_file)
{ 
    strcat(http_file, "GET /");
    strcat(http_file,resourse);
    strcat(http_file," HTTP/1.1\r\n");
    strcat(http_file, "Accept-Language: zh-cn\r\n");
    strcat(http_file, "Connection: Keep-Alive\r\n");
        //strcat ip
    strcat(http_file, "Host: ");
    strcat(http_file, det_ip);
    strcat(http_file, "\r\n");

    strcat(http_file, "Content-Length: 37\r\n");
    strcat(http_file, "\r\n");
    strcat(http_file, "userName=new_andy&password=new_andy\r\n");
    strcat(http_file, "\r\n");
    int flen=strlen(http_file); 
    return flen;
}

int GetHttpResponse(char *http_response)
{
    if(http_response==NULL)
        return -1;
    int lastinfo=0;
    while(*http_response!='\0')
    {
        lastinfo++;
        if(lastinfo<3)
        {
            continue;
        }
        if(http_response[lastinfo]=='\n' && http_response[lastinfo-1]=='\r' && http_response[lastinfo-2]=='\n' && http_response[lastinfo-3]=='\r')
            return lastinfo;
    }
    return 0;
}
long GetHttpFileLen(char *http_response)
{
    char * search_char = "Content-Length: ";
    char * result_char = strstr(http_response,search_char);
    if(result_char==NULL)
        return 0;
    result_char+=strlen(search_char);
    char filelenchar[30];
    int i=0;
    
    while(*result_char!='\0')
    {
        if(*result_char=='\n' || *result_char=='\r')
            break;
        filelenchar[i++] = *result_char++;
    }
    if(i >= 30)
        return -1;
    filelenchar[i]='\0';
    long result=0;
    int j=0;
    while(filelenchar[j]!='\0')
    {
        result=result*10+filelenchar[j++]-48;
    }
    return result;
}