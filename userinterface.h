#ifndef USERINTERFACE_H
#define USERINTERFACE_H
#include "statistics.h"
#include <stdint.h>
#include <unistd.h>
#include <thread>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

#define EXECFLAG_NORMAL 0
#define EXECFLAG_SPEC_CHANNEL 1
#define EXECFLAG_AP 2
#define EXECFLAG_STATION 3
class statistics;


class userinterface
{
private:
	
	statistics *stat;
public:
	uint32_t exec_flag;
	friend void input(userinterface *);
	friend void output(userinterface *);
	userinterface(statistics *,uint32_t );

};


void input(userinterface *);
void output(userinterface *);






#endif
