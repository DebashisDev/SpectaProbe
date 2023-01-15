/*
 * aaaSM.cpp
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#include "aaaSM.h"

void aaaSM::lockAAAMap()
{
	pthread_mutex_lock(&mapAaaLock::lockCount);
	while (mapAaaLock::count == 0)
		pthread_cond_wait(&mapAaaLock::nonzero, &mapAaaLock::lockCount);
	mapAaaLock::count = mapAaaLock::count - 1;
	pthread_mutex_unlock(&mapAaaLock::lockCount);
}

void aaaSM::unLockAAAMap()
{
    pthread_mutex_lock(&mapAaaLock::lockCount);
    if (mapAaaLock::count == 0)
        pthread_cond_signal(&mapAaaLock::nonzero);
    mapAaaLock::count = mapAaaLock::count + 1;
    pthread_mutex_unlock(&mapAaaLock::lockCount);
}

aaaSM::aaaSM(uint16_t id)
{
	this->_name = "aaaSM";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 	  = id;
	this->lastIndex 	  = 0;
	this->curIndex 		  = 0;
	this->curIndexClnUp   = 0;
	this->lastIndexClnUp  = 0;
	this->aaaSMReadyState = false;
	this->pAaaSMInterface = new aaaSMInterface(this->instanceId);
}

aaaSM::~aaaSM()
{ delete(this->pAaaSMInterface); }


bool aaaSM::isAaaSMReady()
{ return aaaSMReadyState; }


void aaaSM::run()
{
	aaaSMReadyState = true;
	curIndexClnUp = lastIndexClnUp = Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
	lastIndex = curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::AAA_SESSION_MANAGER_RUNNING_STATUS[instanceId])
	{
		usleep(Global::SLEEP_TIME);		// 100ms

		curIndexClnUp =  Global::CURRENT_SEC / Global::IP_SESSION_CLEAN_UP_SCAN_FREQ_SEC;
		curIndex = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastIndex != curIndex)
		{
			aaaProcessQueue(lastIndex);
			lastIndex = PKT_READ_NEXT_TIME_INDEX(lastIndex, Global::TIME_INDEX);
		}

		if(curIndexClnUp != lastIndexClnUp)
		{
			pAaaSMInterface->aaaTimeOutCleanSession();	// IP Cleanup
			lastIndexClnUp = curIndexClnUp;
		}
	} /* End Of (Main) While Loop */

	printf("  Aaa SM [%02d] Stopped...\n", instanceId);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void aaaSM::aaaProcessQueue(uint16_t timeIndex)
{
	for(uint16_t i = 0; i < Global::NO_OF_INTERFACES; i++)
		for(uint16_t r = 0; r < Global::ROUTER_PER_INTERFACE[i]; r++)
			processQueue(SmStore::aaaBusy[instanceId][i][r][timeIndex], SmStore::aaaCnt[instanceId][i][r][timeIndex], SmStore::aaaStore[instanceId][i][r][timeIndex]);
}

void aaaSM::processQueue(bool &smBusy, uint32_t &smCnt, std::unordered_map<uint32_t, MPacket> &pkt)
{
	uint32_t recCnt = smCnt;

	if(recCnt > 0)
	{
		smBusy = true;

		for(uint32_t i = 0; i < recCnt; i++)
		{
			aaaProcessPacket(&pkt[i]);
			pkt.erase(i);
		}
		pkt.clear();
		smCnt = 0;
		smBusy = false;
	}
}

void aaaSM::aaaProcessPacket(MPacket *pkt)
{
	Global::SM_AAA_PACKETS_PER_DAY[instanceId] ++;
	pAaaSMInterface->packetEntry(pkt);
}
