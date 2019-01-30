#include "userinterface.h"
#include "statistics.h"

extern char *interface;
extern int elapsed;
extern char date[40];
char kbhit(void)
{
	struct termios oldt, newt;
	int ch;
	int oldf;
	 
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
	 
	ch = getchar();
	return ch; 
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);
	 
	if(ch != EOF)
	{
		ungetc(ch, stdin);
		return -1;
	}
}



userinterface::userinterface(statistics *stat,uint32_t exec_flag)
{
	this->stat = stat;
	this->exec_flag = exec_flag;
	thread t1(output,this);
	t1.detach();
	thread t2(input,this);
	t2.detach();
	
}


void input(userinterface *ui)
{
	while(1)
	{
		switch(kbhit())
		{
		case 'a':
		{
			ui->exec_flag = (ui->exec_flag == EXECFLAG_AP ? EXECFLAG_STATION : EXECFLAG_AP);
			break;
		}
		default :break;
		}
	
	}
}


void output(userinterface *ui)
{
	
	map<string,struct ap_list_entry *> *ap_list= &ui->stat->ap_list;
	map<struct probe_pair,struct sta_list_entry *> *response_list= &ui->stat->response_list;
	map<string,struct sta_list_entry *> *request_list= &ui->stat->request_list;
	
	
	while(1)
	{
		char temp[200];
		int channel = rand()%15;
		sprintf(temp,"iwconfig %s channel %d",interface,channel);
		system(temp);
		int i=0;
		if(ui->exec_flag == EXECFLAG_AP)
		{	
			map<string,struct ap_list_entry *>::iterator aiterator = ap_list->begin();
			map<string,struct ap_list_entry *>::iterator aender = ap_list->end();			
			printf("\033[2J");
			printf("\033[0;0H");
			printf("CH %2d ][ elapsed time %d]%s\n",channel,elapsed,date);		
			printf("\tBSSID\t\tPWR  Beacons  #Data    #/s      CH      MB      ENC     CIPHER  AUTH    ESSID\n\n");
			for(; i < 55 && aiterator != aender ; i++, aiterator++ )
			{	
				cout<<aiterator->second->BSSID<<"        ";
				printf("%3d\t",aiterator->second->PWR);
				cout<<aiterator->second->Beacons<<"\t";
				cout<<aiterator->second->nr_Data<<"\t";
				printf("%d\t",(elapsed == 0) ? 0 : aiterator->second->nr_Data / elapsed);
				cout<<aiterator->second->CH<<"\t";
				cout<<aiterator->second->MB<<"\t";
				cout<< aiterator->second->ENC <<"\t";
				cout<< aiterator->second->CIPHER <<"\t";
				cout<< aiterator->second->AUTH <<"\t";
				cout<<aiterator->second->ESSID;
				printf("\033[%d;0H",i+3);
			
			}		
		}
		else if(ui->exec_flag == EXECFLAG_STATION)
		{
			map<struct probe_pair,struct sta_list_entry *>::iterator piterator = response_list->begin();
			map<struct probe_pair,struct sta_list_entry *>::iterator pender = response_list->end();	
			map<string,struct sta_list_entry *>::iterator qiterator = request_list->begin();
			map<string,struct sta_list_entry *>::iterator qender = request_list->end();

			printf("\033[2J");
			printf("\033[0;0H");
			printf("CH %2d ][ elapsed time %d]%s\n",channel,elapsed,date);			
			
			printf("\tBSSID\t\t\tSTATION\t\tPWR     Rate    LOST   Frames   Probe\n\n");
			for(; i < 55 && qiterator != qender ;i++,qiterator++)
			{	
				cout<<qiterator->second->BSSID<<"        ";
				cout<<qiterator->second->STATION<<"\t";
				printf("%3d\t",qiterator->second->PWR);
				printf("%d-%d\t",qiterator->second->LRate,qiterator->second->RRate);
				printf("%d\t",qiterator->second->lost);
				printf("%d\t",qiterator->second->Frames);
				cout<<qiterator->second->Probe;
				printf("\033[%d;0H",i+3);
			}		
			for(; i < 55 && piterator != pender ;i++,piterator++)
			{	
				cout<<piterator->second->BSSID<<"        ";
				cout<<piterator->second->STATION<<"\t";
				printf("%3d\t",piterator->second->PWR);
				printf("%d-%d\t",piterator->second->LRate,piterator->second->RRate);
				printf("%d\t",piterator->second->lost);
				printf("%d\t",piterator->second->Frames);
				cout<<piterator->second->Probe;
				printf("\033[%d;0H",i+3);
			}	

		}
		usleep(70000);
	}
}
