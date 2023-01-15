/*
 * RadiusFlusher.cpp
 *
 *  Created on: 17-Sep-2019
 *      Author: Debashis
 */

#include "aaaFlusher.h"

aaaFlusher::aaaFlusher(uint16_t id)
{
	_thisLogLevel = 0;
	this->_name = "aaaFlusher";
	this->setLogLevel(Log::theLog().level());

	this->instanceId 		= id;
	this->initStatus 	= false;
	rfUtility 			= new aaaFlushUtility();
}

aaaFlusher::~aaaFlusher()
{ delete(rfUtility); }

bool aaaFlusher::isInitialized()
{ return initStatus; }

void aaaFlusher::run()
{
	uint16_t lastTidx, curTidx;
	initStatus = true;

	lastTidx = curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

	while(Global::AAA_FLUSHER_RUNNING_STATUS)
	{
		usleep(Global::SLEEP_TIME);
		curTidx = PKT_READ_TIME_INDEX(Global::CURRENT_EPOCH_SEC, Global::TIME_INDEX);

		while(lastTidx != curTidx)
		{
			processData(lastTidx);
			lastTidx = PKT_READ_NEXT_TIME_INDEX(lastTidx, Global::TIME_INDEX);
		}
	}
	printf("  AAA Flusher Stopped...\n");
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

void aaaFlusher::processData(uint16_t tIdx)
{
	openAaaXdrFile(Global::CURRENT_MIN, Global::CURRENT_HOUR, Global::CURRENT_DAY, Global::CURRENT_MONTH, Global::CURRENT_YEAR);

	for(uint16_t sm = 0; sm < Global::AAA_SESSION_MANAGER_INSTANCES; sm++)
		getAaaData(flusherStore::aaaCnt[instanceId][sm][tIdx], flusherStore::aaa[instanceId][sm][tIdx]);

	closeAaaXdrFile();
}

void aaaFlusher::getAaaData(uint32_t &fCnt, std::unordered_map<uint32_t, aaaSession> &flushMap)
{
	uint32_t cnt = fCnt;

	if(cnt > 0)
	{
		for(uint32_t i = 0; i < cnt; i++)
		{
			if(createAaaXdrData(&flushMap[i]))
				aaaXdrHandler << std::string(csvXdr) << endl;

			flushMap.erase(i);
			fCnt--;
		}
		flushMap.clear();
	}
	fCnt = 0;
}

bool aaaFlusher::createAaaXdrData(aaaSession *pAaaSession)
{
	if(pAaaSession == NULL)
			return false;

	csvXdr[0] = 0;
	rfUtility->buildAaaXdr(pAaaSession, csvXdr);

	if(strlen(csvXdr) <= 0)
		return false;
	else
		return true;

}

void aaaFlusher::openAaaXdrFile(uint16_t min, uint16_t hour, uint16_t day, uint16_t month, uint16_t year)
{
	char filePath[300];
	filePath[0] = 0;

	sprintf(filePath, "%s%s/%s_%d-%02d-%02d-%02d-%02d_%02d.csv",
					Global::XDR_DIR.c_str(),
					"aaa",
					"aaa",
					year,
					month,
					day,
					hour,
					min,
					instanceId);
	aaaXdrHandler.open((char *)filePath, ios :: out | ios :: app);

	filePath[0] = 0;
}

void aaaFlusher::closeAaaXdrFile()
{ aaaXdrHandler.close(); }
