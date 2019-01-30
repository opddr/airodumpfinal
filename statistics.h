#ifndef STATISTICS_H
#define STATISTICS_H

#include "userinterface.h"
#include <stdint.h>
#include <pcap.h>
#include <map>
#include <string>
#include <iostream>
#include <cstdio>

using namespace std;


class userinterface;
void output(userinterface *ui);



struct ap_list_entry
{
	string BSSID;
	int16_t PWR;
	uint32_t Beacons;
	uint32_t nr_Data;
	uint32_t nr_per_sec;
	uint32_t CH;
	string MB;
	string ENC;
	string CIPHER; 
	string AUTH;
	string ESSID;
	ap_list_entry()
	{
		BSSID = string("");
		ESSID = string("");
		MB = string("");
		ENC = string("");
		CIPHER = string("");
		AUTH = string("");
		PWR = Beacons = nr_Data = nr_per_sec = CH = 0;
	}
};
struct sta_list_entry
{
	string BSSID;
	string STATION;
	int32_t PWR;
	uint32_t LRate;
	uint32_t RRate;
	uint32_t seq;
	uint32_t lost;
	uint32_t Frames;
	string Probe;
	sta_list_entry()
	{
		BSSID = string("");
		STATION = string("");
		Probe = string("");
		PWR = lost = Frames = seq = LRate = RRate = 0;
	}
};

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

struct probe_pair
{
	string AP,STATION;
	bool operator==(const struct probe_pair &o) const
	{
		return AP == o.AP && STATION == o.STATION;
	}

	bool operator<(const struct probe_pair &o)  const
	{
		return AP < o.AP || (AP == o.AP && STATION < o.STATION);
	}
};


class statistics
{
private:
	map<string, struct ap_list_entry *> ap_list;
	map<probe_pair, struct sta_list_entry *> response_list;
	map<string, struct sta_list_entry *> request_list;
public:	
	friend void output(userinterface *ui);
	void parser(const u_char *packet, uint32_t m);
	~statistics()
	{
		map<string,struct ap_list_entry *>::iterator aiterator = ap_list.begin();
		map<struct probe_pair,struct sta_list_entry *>::iterator piterator = response_list.begin();
		map<string,struct sta_list_entry *>::iterator qiterator = request_list.begin();

		for(;aiterator != ap_list.end();aiterator++)
		{
			delete aiterator->second;
		}
		for(;piterator != response_list.end();piterator++)
		{
			delete piterator->second;
		}
		for(;qiterator != request_list.end();qiterator++)
		{
			delete qiterator->second;
		}
	}
};




#endif
