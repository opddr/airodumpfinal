#include <sys/socket.h>
#include <string>
#include <iostream>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <stdint.h>




using namespace std;

struct radiotap
{
	uint16_t it_len;
	uint32_t it_present;
	uint8_t flags;
	uint8_t rate;
	uint16_t channel_freq;
	uint16_t channel_flags;
	int8_t power;
};

struct ieee802_11
{
	uint8_t fc_type;
	uint8_t fc_flags;
	char APmac[6];
	char STAmac[6];
	uint16_t fraseq;	
	long long timestamp;
	uint16_t capabilities;
	uint8_t channel;
	uint8_t max_sup_rate;

	uint32_t group_chiper_suite;
	uint32_t akm_suite;
	uint8_t auth;
	string ESSID;
};






int main(int argc,char **argv)
{
	if(argc != 2)
	{
		cout<<"Usage : ./airodump <interface>"<<endl;
		exit(1);
	}
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);	
	if(handle == NULL)
	{
		fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
		return -1;
	}
		
	while(1)
	{
		int res,index=0;
		struct pcap_pkthdr *header;
		const u_char *packet;
		const u_char *radiotap;
		const u_char *ieee802_11;


		struct radiotap radio = {0} ;


		printf("\n\n\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");			

		res = pcap_next_ex(handle,&header,&packet);
		
		radio.it_len = *((uint16_t *)(packet+2));	
		cout<<"radiotap length : "<<radio.it_len<<endl;

		radio.it_present = *((uint32_t *)(packet+4));
		cout<<"radiotap flags : "<<hex<<radio.it_present<<endl;

		
		
		index += 1+1+2+4;

		if(radio.it_present & 0x80000000)
			index += 4;
		if(radio.it_present & 1)		
		{
			index+=8;
		}	//TSFT
		if(radio.it_present & 2)		
		{
			radio.flags = *((uint8_t *)( packet+index));
			index += 1;
		}	//Flags
		if(radio.it_present & 4)			
		{
			radio.rate = *((uint8_t *)( packet+index));
			index += 1;
		}	//Rate
		if(radio.it_present & 8)		
		{
			radio.channel_freq = *((uint16_t *)(packet+index));			
			index += 2;
			radio.channel_flags = *((uint16_t *)(packet+index));
			index += 2;
		}	//Channel
		if(radio.it_present & 16)		
		{

			index += 1;
		}	//FHSS
		if(radio.it_present & 32)		
		{
			radio.power = *((int8_t *)(packet+index));
			index += 1;
		}	//dBm signal		

		

		printf("radiotap_flags : %hhx\n",radio.flags);
		printf("radiotap_rate : %hhx\n",radio.rate);		
		printf("radiotap_channel_freq : %hx\n",radio.channel_freq);
		printf("radiotap_channel_flags : %hx\n",radio.channel_flags);
		printf("radiotap_power : %hhd\n",radio.power);

///////////////////////////////////////////////////////////////////////////////////////////

		

		index = 0 ;
		ieee802_11 = packet + radio.it_len;
		struct ieee802_11 ieee = {0};		

		ieee.fc_type = *((uint8_t *)(ieee802_11 + index));
		ieee.fc_flags = *((uint8_t *)(ieee802_11 + index + 1));
		index+=2; //frame control

		index+=2; // duration
			
		printf("type,flags = %hhx, %hhx\n",ieee.fc_type,ieee.fc_flags);
		
		if( ieee.fc_type &  8)	// data frame
		{
			printf("data frame \n");
			

			ieee.APmac[0]= ieee802_11[index+6];
			ieee.APmac[1]= ieee802_11[index+7];
			ieee.APmac[2]= ieee802_11[index+8];
			ieee.APmac[3]= ieee802_11[index+9];
			ieee.APmac[4]= ieee802_11[index+10];
			ieee.APmac[5]= ieee802_11[index+11];

			ieee.STAmac[0]= ieee802_11[index+0];
			ieee.STAmac[1]= ieee802_11[index+1];
			ieee.STAmac[2]= ieee802_11[index+2];
			ieee.STAmac[3]= ieee802_11[index+3];
			ieee.STAmac[4]= ieee802_11[index+4];
			ieee.STAmac[5]= ieee802_11[index+5];
			
			printf("AP : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
			printf("STA : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);

			index+=18;	

			ieee.fraseq = *((uint16_t *)(ieee802_11+index));
			index +=2;

			printf("seq : %d, frag : %hx\n",ieee.fraseq>>4,ieee.fraseq & 0xf);
			
		}
		else if(ieee.fc_type == 0x80)
		{
			printf("beacon frame \n");

			ieee.APmac[0]= ieee802_11[index+12];
			ieee.APmac[1]= ieee802_11[index+13];
			ieee.APmac[2]= ieee802_11[index+14];
			ieee.APmac[3]= ieee802_11[index+15];
			ieee.APmac[4]= ieee802_11[index+16];
			ieee.APmac[5]= ieee802_11[index+17];
			
			printf("AP : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);

			index+=18;
			
			ieee.fraseq = *((uint16_t *)(ieee802_11+index));
			index +=2;

			printf("seq : %d, frag : %hx\n",ieee.fraseq>>4,ieee.fraseq & 0xf);


			ieee.timestamp = *((long long *)(ieee802_11 + index));
			index+=8;
			printf("timestamp = 0x%llx\n",ieee.timestamp);

			index += 2; // beacon interval;

			ieee.capabilities = *((uint16_t *)(ieee802_11 + index));
			index+=2; // capabilities
			printf("capabilities : 0x%hx\n",ieee.capabilities);
						
			uint16_t suite_count=0;
			uint8_t tag = 0;
			uint8_t tag_length = 0;
			while(header->len - radio.it_len - 4 >= index)
			{
				tag = *((uint8_t *)(ieee802_11 + index));
				tag_length = *((uint8_t *)(ieee802_11 + index + 1));
				index += 2;
				printf("tag : %hhu, tag_leng : %hhu \n",tag,tag_length);
				switch(tag)
				{



				case 0:
				{
					int i=0;
					char temp[200]={0};
					for(i=0;i<tag_length;i++)
						temp[i] = ieee802_11[index + i];
					temp[i] = 0;
					ieee.ESSID = string(temp);
					break;
				}
				case 1:
				{
					ieee.max_sup_rate = ieee802_11[index + tag_length - 1];
					break;

				}
				case 3:
				{
					ieee.channel = ieee802_11[index];
					break;
				}
				case 48:
				{		
					index += 2; // version + l
					ieee.group_chiper_suite = *((uint32_t*)(ieee802_11+index));
					index += 4;
					
					suite_count = *((uint16_t*)(ieee802_11+index));
					index += 2; // pairwise suite count
					index += suite_count * 4; // pairwise suite list

					index+=2; // akm count					
					ieee.akm_suite = *((uint32_t*)(ieee802_11+index));
					goto out;
					
					break;
				}
				case 50:
				{
					ieee.max_sup_rate = ieee802_11[index + tag_length - 1];
					break;
				}
				default:break;
				}
				index += tag_length;
			}
out:
			cout<<"ESSID : "<<ieee.ESSID << endl;
			printf("max_supported rate : %hhx\n",ieee.max_sup_rate);
			printf("channel : %hhd\n",ieee.channel);
			printf("cipher : %x\n",ieee.group_chiper_suite);
			printf("akm : %x",ieee.akm_suite);
					
		}

		else if(ieee.fc_type == 0x50)
		{
			printf("probe response frame \n");

			ieee.APmac[0]= ieee802_11[index+12];
			ieee.APmac[1]= ieee802_11[index+13];
			ieee.APmac[2]= ieee802_11[index+14];
			ieee.APmac[3]= ieee802_11[index+15];
			ieee.APmac[4]= ieee802_11[index+16];
			ieee.APmac[5]= ieee802_11[index+17];

			ieee.STAmac[0]= ieee802_11[index+0];
			ieee.STAmac[1]= ieee802_11[index+1];
			ieee.STAmac[2]= ieee802_11[index+2];
			ieee.STAmac[3]= ieee802_11[index+3];
			ieee.STAmac[4]= ieee802_11[index+4];
			ieee.STAmac[5]= ieee802_11[index+5];
			
			printf("AP : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
			printf("STA : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);

			index+=18;
			
			ieee.fraseq = *((uint16_t *)(ieee802_11+index));
			index +=2;

			printf("seq : %d, frag : %hx\n",ieee.fraseq>>4,ieee.fraseq & 0xf);
			
			ieee.timestamp = *((long long *)(ieee802_11 + index));
			index+=8;
			printf("timestamp = 0x%llx\n",ieee.timestamp);

			index += 2; // beacon interval;

			ieee.capabilities = *((uint16_t *)(ieee802_11 + index));
			index+=2; // capabilities
			printf("capabilities : 0x%hx\n",ieee.capabilities);
						
			uint16_t suite_count=0;
			uint8_t tag = 0;
			uint8_t tag_length = 0;
			while(header->len - radio.it_len - 4 >= index)
			{
				tag = *((uint8_t *)(ieee802_11 + index));
				tag_length = *((uint8_t *)(ieee802_11 + index + 1));
				index += 2;
				printf("tag : %hhu, tag_leng : %hhu \n",tag,tag_length);
				switch(tag)
				{
				case 0:
				{
					int i=0;
					char temp[200]={0};
					for(i=0;i<tag_length;i++)
						temp[i] = ieee802_11[index + i];
					temp[i] = 0;
					ieee.ESSID = string(temp);
					break;	
				}
				default:break;
				}
				index += tag_length;
			}
			cout<<"ESSID : "<<ieee.ESSID << endl;
			printf("max_supported rate : %hhx\n",ieee.max_sup_rate);
			printf("channel : %hhd\n",ieee.channel);
			printf("cipher : %x\n",ieee.group_chiper_suite);
			printf("akm : %x",ieee.akm_suite);
		}
		else if(ieee.fc_type == 0x40)
		{
			printf("probe request frame \n");

			
			ieee.APmac[0]= ieee802_11[index+12];
			ieee.APmac[1]= ieee802_11[index+13];
			ieee.APmac[2]= ieee802_11[index+14];
			ieee.APmac[3]= ieee802_11[index+15];
			ieee.APmac[4]= ieee802_11[index+16];
			ieee.APmac[5]= ieee802_11[index+17];

			ieee.STAmac[0]= ieee802_11[index+6];
			ieee.STAmac[1]= ieee802_11[index+7];
			ieee.STAmac[2]= ieee802_11[index+8];
			ieee.STAmac[3]= ieee802_11[index+9];
			ieee.STAmac[4]= ieee802_11[index+10];
			ieee.STAmac[5]= ieee802_11[index+11];
			
			printf("AP : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
			printf("STA : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);

			index+=18;
			
			ieee.fraseq = *((uint16_t *)(ieee802_11+index));
			index +=2;

			printf("seq : %d, frag : %hx\n",ieee.fraseq>>4,ieee.fraseq & 0xf);
			
		}
		else
			continue;

	}
	
}









