#include "statistics.h"




void statistics::parser(const u_char *packet, uint32_t header_len)
{
	uint32_t index = 0;
	const u_char *radiotap;
	const u_char *ieee802_11;
	struct radiotap radio = {0} ;
	struct ieee802_11 ieee = {0};

	if(*((uint8_t *)(packet)) != 0)
		return ;
	radio.it_len = *((uint16_t *)(packet+2));	

	radio.it_present = *((uint32_t *)(packet+4));	
		
	index += 1 + 1 + 2 + 4;

	if(radio.it_present & 0x80000000)
		index += 4;
	if(radio.it_present & 1)//TSFT		
	{
		index+=8;
	}
	if(radio.it_present & 2)//Flags		
	{
		radio.flags = *((uint8_t *)( packet+index));
		index += 1;
	}
	if(radio.it_present & 4)//Rate			
	{
		radio.rate = *((uint8_t *)( packet+index));
		index += 1;
	}
	if(radio.it_present & 8)//Channel		
	{
		radio.channel_freq = *((uint16_t *)(packet+index));			
		index += 2;
		radio.channel_flags = *((uint16_t *)(packet+index));
		index += 2;
	}
	if(radio.it_present & 16)//FHSS		
	{
		index += 1;
	}	
	if(radio.it_present & 32)//dBm signal		
	{
		radio.power = *((int8_t *)(packet+index));
		index += 1;
	}		


///////////////////////////////////////////////////////////////////////////////////////////

	index = 0 ;
	ieee802_11 = packet + radio.it_len;
		
	ieee.fc_type = *((uint8_t *)(ieee802_11 + index));
	ieee.fc_flags = *((uint8_t *)(ieee802_11 + index + 1));
	index+=2; //frame control
	index+=2; // duration
		
	if( ieee.fc_type &  8)	// data frame
	{

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

		index+=18;	

		ieee.fraseq = *((uint16_t *)(ieee802_11+index));
		index +=2;

		char temps[20];
		sprintf(temps,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
		string bssid = string(temps);	
		sprintf(temps,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);
		string stamac = string(temps);	

		if(ap_list.find(bssid) != ap_list.end())
		{
			struct ap_list_entry *temp= ap_list.find(bssid)->second;
			temp->nr_Data++;
		}
	
		struct probe_pair ppair = {bssid,stamac};
		if( response_list.find(ppair) != response_list.end() )
		{
			struct  sta_list_entry *temp= response_list.find(ppair)->second;
			temp->Frames++;
		}
		if( request_list.find(stamac) != request_list.end() )
		{
			struct sta_list_entry *temp= request_list.find(stamac)->second;
			temp->Frames++;
		}			
	}
	else if(ieee.fc_type == 0x80) // beacon
	{
		ieee.APmac[0]= ieee802_11[index+12];
		ieee.APmac[1]= ieee802_11[index+13];
		ieee.APmac[2]= ieee802_11[index+14];
		ieee.APmac[3]= ieee802_11[index+15];
		ieee.APmac[4]= ieee802_11[index+16];
		ieee.APmac[5]= ieee802_11[index+17];
			
		index+=18;
			
		ieee.fraseq = *((uint16_t *)(ieee802_11+index));
		index +=2;

		ieee.timestamp = *((long long *)(ieee802_11 + index));
		index+=8;

		index += 2; // beacon interval;

		ieee.capabilities = *((uint16_t *)(ieee802_11 + index));
		index+=2; // capabilities
						
		uint16_t suite_count=0;
		uint8_t tag = 0;
		uint8_t tag_length = 0;
		ieee.group_chiper_suite = 0;
		while(header_len - radio.it_len - 4 >= index)
		{
			tag = *((uint8_t *)(ieee802_11 + index));
			tag_length = *((uint8_t *)(ieee802_11 + index + 1));
			index += 2;
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
				index += 2; // version
				ieee.group_chiper_suite = *((uint32_t*)(ieee802_11+index));
				index += 4;
				
				suite_count = *((uint16_t*)(ieee802_11+index));
				index += 2;
				index += suite_count * 4; // cipher suite list
				
				suite_count = *((uint16_t*)(ieee802_11+index));
				index+=2; // akm count	

				ieee.akm_suite = *((uint32_t*)(ieee802_11+index));
				goto out1;
				
				break;
			}
			case 50:
			{
				ieee.max_sup_rate = ieee802_11[index + tag_length - 1];
				break;	
			}
			default:
			
				break;			
			}
			index += tag_length;
		}
out1:
		char temp[200];
		struct ap_list_entry *ap = new struct ap_list_entry;

		sprintf(temp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
		ap->BSSID = string(temp);
		ap->PWR = radio.power;
		ap->Beacons = 1;
		ap->nr_Data = 0;
		ap->nr_per_sec = 0;
		ap->CH = ieee.channel;
		sprintf(temp,"%d",ieee.max_sup_rate / 2);
		ap->MB = string(temp);
		ap->ESSID = ieee.ESSID;

		switch(ieee.group_chiper_suite)
		{
		case 0xac0f00:ap->CIPHER = string("group");break;
		case 0x1ac0f00:ap->ENC = string("WEP");ap->CIPHER = string("WEP40");break;
		case 0x2ac0f00:ap->ENC = string("WPA");ap->CIPHER = string("TKIP");break;
		case 0x4ac0f00:ap->ENC = string("WPA2");ap->CIPHER = string("CCMP");break;
		case 0x5ac0f00:ap->ENC = string("WEP");ap->CIPHER = string("WEP104");break;
		case 0x6ac0f00:ap->CIPHER = string("BIP");break;
		case 0:ap->ENC = string("OPN");break;
		default:break;
		}		
		
		switch(ieee.akm_suite)
		{
		case 0xac0f00:ap->AUTH=string("reserved");break;
		case 0x1ac0f00:ap->AUTH=string("MGT");break;
		case 0x2ac0f00:ap->AUTH=string("PSK");break;
		default:break;
		}
		
		if(ap_list.find(ap->BSSID) == ap_list.end())
		{
			ap_list.insert(pair<string,struct ap_list_entry *>(ap->BSSID,ap));
		}
		else
		{
			struct ap_list_entry *temp= ap_list.find(ap->BSSID)->second;
			temp->Beacons ++;
			temp->PWR = ap->PWR;
			temp->ESSID = ap->ESSID;
		}
 	}

	else if(ieee.fc_type == 0x50) // probe response
	{
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

		index+=18;
			
		ieee.fraseq = *((uint16_t *)(ieee802_11+index));
		index +=2;
		ieee.timestamp = *((long long *)(ieee802_11 + index));
		index+=8;

		index += 2; // beacon interval;

		ieee.capabilities = *((uint16_t *)(ieee802_11 + index));
		index+=2; // capabilities
						
		uint16_t suite_count=0;
		uint8_t tag = 0;
		uint8_t tag_length = 0;
		while(header_len - radio.it_len - 4 >= index)
		{
			tag = *((uint8_t *)(ieee802_11 + index));
			tag_length = *((uint8_t *)(ieee802_11 + index + 1));
			index += 2;
			
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
				goto out2;	
			}
			default:break;
			}
			index += tag_length;
		}
out2:
		char temp[200];
		int t=0;
		struct sta_list_entry *sta = new struct sta_list_entry;

		sprintf(temp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
		sta->BSSID = string(temp);
		sprintf(temp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);
		sta->STATION = string(temp);
		sta->PWR = radio.power;
		sta->RRate = radio.rate / 2;
		sta->seq = ieee.fraseq >> 4;
		sta->lost = 0;
		sta->Frames = 1;
		sta->Probe = ieee.ESSID;

		struct probe_pair ppair= {sta->BSSID, sta->STATION};
		if(response_list.find(ppair) == response_list.end())
		{
			response_list[ppair] = sta;
		}
		else
		{
			struct sta_list_entry *temp= response_list.find(ppair)->second;
			int temps = temp->seq;
			temp->BSSID = sta->BSSID;
			temp->PWR = sta->PWR;
			temp->RRate = sta->RRate;
			temp->seq = sta->seq;
			//temp->lost = (temps > sta->seq) ? 0 : sta->seq - temps;
			temp->lost = (temps >= sta->seq)? 0 : sta->seq - temps - 1;
			temp->Probe = sta->Probe;
			temp->Frames ++;
		}			
	}
	else if(ieee.fc_type == 0x40) // probe request
	{
			
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

		index+=18;
			
		ieee.fraseq = *((uint16_t *)(ieee802_11+index));
		index +=2;

		uint16_t suite_count=0;
		uint8_t tag = 0;
		uint8_t tag_length = 0;
		while(header_len - radio.it_len - 4 >= index)
		{
			tag = *((uint8_t *)(ieee802_11 + index));
			tag_length = *((uint8_t *)(ieee802_11 + index + 1));
			index += 2;
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
				goto out3;	
			}
			default:break;
			}
			index += tag_length;
		}
out3:
		char temp[200];
		struct sta_list_entry *sta = new struct sta_list_entry;

		sprintf(temp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.APmac[0],ieee.APmac[1],ieee.APmac[2],ieee.APmac[3],ieee.APmac[4],ieee.APmac[5]);
		sta->BSSID = string(temp);
		sprintf(temp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",ieee.STAmac[0],ieee.STAmac[1],ieee.STAmac[2],ieee.STAmac[3],ieee.STAmac[4],ieee.STAmac[5]);
		sta->STATION = string(temp);
		sta->PWR = radio.power;
		sta->LRate = radio.rate / 2;
		sta->seq =  0xffffffff;
		sta->lost = 0;
		sta->Frames = 1;
		sta->Probe = ieee.ESSID;


		if(request_list.find(sta->STATION) == request_list.end())
		{
			request_list.insert(pair<string,sta_list_entry *>(sta->STATION,sta));
		}
		else
		{
			struct sta_list_entry *temp= request_list.find(sta->STATION)->second;

			temp->PWR = sta->PWR;
			temp->RRate = sta->RRate;
			temp->Probe = sta->Probe;
			temp->Frames ++;
		}
	}
	else
		return ;
}




