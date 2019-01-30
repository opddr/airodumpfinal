#include "main.h"

char *interface;
int elapsed = 0;
char date[40];
#include <time.h>

void timer()
{
	while(1)
	{
		sleep(4);
		static long long prior_time = 0;
		time_t t = time(NULL);
		struct tm tm = *localtime(&t);

		elapsed += prior_time == 0 ? 4 :  tm.tm_sec - prior_time;
		prior_time = tm.tm_sec;
	}
}
int main(int argc, char** argv)
{

	int i;
	;
	uint32_t exec_flag=EXECFLAG_AP;
	int specific_channel;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char temp[200];

	if(argc == 1)
	{
		printf("Usage : ./airodump [options] <interface>");
		exit(1);
	}

	for(i=1;i<argc;i++)
	{
		if(strcmp(argv[i],"-c") == 0)
		{
			exec_flag = EXECFLAG_SPEC_CHANNEL;
			specific_channel = atoi(argv[i+1]);
			i++;
		}
		else
		{
			interface = argv[i];
		}
	}
	


	statistics stat;
	thread t1(timer);	
	userinterface ui(&stat,exec_flag);	
	handle = pcap_open_live(interface,BUFSIZ,1,1000,errbuf);	
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	sprintf(date,"[ %d-%d-%d %d:%d ]", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min);

	while(1)
	{
		int res;
		struct pcap_pkthdr *header;
		const u_char *packet;

		res = pcap_next_ex(handle,&header,&packet);
		if(res > 0)
			stat.parser(packet,header->len);

	}
	return 0;
}
