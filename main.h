#ifndef MAIN_H
#define MAIN_H

#include "userinterface.h"
#include "statistics.h"
#include <sys/socket.h>
#include <string>
#include <iostream>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdint.h>

using namespace std;



#define EXECFLAG_NORMAL 0
#define EXECFLAG_SPEC_CHANNEL 1
#define EXECFLAG_AP 2
#define EXECFLAG_STATION 3

class statistics;
class userinterface;



#endif
