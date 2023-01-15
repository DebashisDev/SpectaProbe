/*
 * radiusSessionManager.cpp
 *
 *  Created on: Oct 22, 2016
 *      Author: Debashis
 */

#include "aaaSMInterface.h"

aaaSMInterface::aaaSMInterface(uint16_t id)
{
	this->_name = "aaaSMInterface";
	this->setLogLevel(Log::theLog().level());

	this->instanceId = id;
	this->cleanUpCnt = 0;
}

aaaSMInterface::~aaaSMInterface()
{ }

void aaaSMInterface::aaaLockMap()
{
	    pthread_mutex_lock(&mapAaaLock::lockCount);
	    while (mapAaaLock::count == 0)
	        pthread_cond_wait(&mapAaaLock::nonzero, &mapAaaLock::lockCount);
	    mapAaaLock::count = mapAaaLock::count - 1;
	    pthread_mutex_unlock(&mapAaaLock::lockCount);
}

void aaaSMInterface::aaaUnLockMap()
{
    pthread_mutex_lock(&mapAaaLock::lockCount);
    if (mapAaaLock::count == 0)
        pthread_cond_signal(&mapAaaLock::nonzero);
    mapAaaLock::count = mapAaaLock::count + 1;
    pthread_mutex_unlock(&mapAaaLock::lockCount);
}


void aaaSMInterface::packetEntry(MPacket *msgObj)
{
	switch(msgObj->aaaCode)
	{
			case ACCESS_REQUEST:		//1
							processAccessRequest(msgObj);
							break;

			case ACCESS_ACCEPT:			//2
			case ACCESS_REJECT:			//3
							processAccessResponse(msgObj);
							break;

			case ACCOUNTING_REQUEST:	//4
							processAccountingRequest(msgObj);
							break;

			case ACCOUNTING_RESPONSE:	//5
							processAccountingResponse(msgObj);
							break;
			default:
							break;
	}
}

void aaaSMInterface::processAccessRequest(MPacket *msgObj)
{
	bool found = false;
	bool eraseFlag = false;

	aaaSession *pRadiusSession = getAccessSession(msgObj, &found);

	if(found)		/* Record Already Exist with Response*/
	{
		if(pRadiusSession->respCode == ACCESS_ACCEPT || pRadiusSession->respCode == ACCESS_REJECT)
		{
			createSession(pRadiusSession, msgObj);
			eraseFlag = true;
			flushRadiusSession(pRadiusSession, eraseFlag, FLUSH_RSP_REQ);
		}
	}
	else if(!found) 	/* New Request Packet */
	{ createSession(pRadiusSession, msgObj); }
}

void aaaSMInterface::processAccessResponse(MPacket *msgObj)
{
	bool found = false;
	aaaSession *pRadiusSession;

	pRadiusSession = getAccessSession(msgObj, &found);

	if(found) 		/* Found Request to Response */
	{
		if(pRadiusSession->reqCode == ACCESS_REQUEST)
		{
			switch(msgObj->aaaCode)
			{
				case ACCESS_ACCEPT:
				case ACCESS_REJECT:
						updateSession(pRadiusSession, msgObj);
						flushRadiusSession(pRadiusSession, true, FLUSH_REQ_RSP);
						break;
			}
		}
	}
	else if(!found)	/* We may not intrested to keep the Access Response Packet (May be blocked)*/
	{ updateSession(pRadiusSession, msgObj); }
}

void aaaSMInterface::processAccountingRequest(MPacket *msgObj)
{
	bool found = false;
	bool eraseFlag = false;
	aaaSession *pRadiusSession;

	pRadiusSession = getAccountingSession(msgObj, &found);

	if(found)		/* Record Already Exist with Response*/
	{
		if(pRadiusSession->respCode == ACCOUNTING_RESPONSE)
		{
			createSession(pRadiusSession, msgObj);
			updateGlbIPTable(pRadiusSession);					/* Update IP and User Id Map */
			eraseFlag = true;
			flushRadiusSession(pRadiusSession, eraseFlag, FLUSH_RSP_REQ);
		}
	}
	else if(!found) 			/* New Request Packet */
	{ createSession(pRadiusSession, msgObj); }
}

void aaaSMInterface::processAccountingResponse(MPacket *msgObj)
{
	bool found = false;
	bool eraseFlag = false;

	aaaSession *pRadiusSession;

	pRadiusSession = getAccountingSession(msgObj, &found);

	if(found) 		/* Found Request to Response */
	{
		if(pRadiusSession->reqCode == ACCOUNTING_REQUEST)
		{
			updateSession(pRadiusSession, msgObj);
			updateGlbIPTable(pRadiusSession);
			eraseFlag = true;
			flushRadiusSession(pRadiusSession, eraseFlag, FLUSH_REQ_RSP);
		}
	}
	else if(!found)		/* We may not intrested to keep the Accounting Response Packet (May be blocked) */
	{ updateSession(pRadiusSession, msgObj); }
}

aaaSession* aaaSMInterface::getAccessSession(MPacket *msgObj, bool *found)
{
	aaaSession *pRadiusSession = NULL;
	uint16_t mIndex = msgObj->aaaIdentifier;

	getSessionKey(msgObj);

	std::map<uint64_t, aaaSession>::iterator it = radiusAccessMap[mIndex].find(msgObj->ipv4FlowId);

	if(it != radiusAccessMap[mIndex].end())
	{
		pRadiusSession = &it->second;
		*found = true;
	}
	else
	{
			aaaSession newRadiusObj;
			newRadiusObj.mapIndex = mIndex;
			radiusAccessMap[mIndex][msgObj->ipv4FlowId] = newRadiusObj;
			pRadiusSession = &radiusAccessMap[mIndex][msgObj->ipv4FlowId];
			*found = false;
	}
	return pRadiusSession;
}

aaaSession* aaaSMInterface::getAccountingSession(MPacket *msgObj, bool *found)
{
	aaaSession *pRadiusSession = NULL;
	int index = msgObj->aaaIdentifier;

	getSessionKey(msgObj);

	std::map<uint64_t, aaaSession>::iterator it = radiusAccountingMap[index].find(msgObj->ipv4FlowId);
	if(it != radiusAccountingMap[index].end()) {
		pRadiusSession = &it->second;
		*found = true;
	}
	else
	{
			aaaSession newRadiusObj;
			newRadiusObj.mapIndex = index;
			newRadiusObj.aaaKey = msgObj->ipv4FlowId;
			radiusAccountingMap[index][msgObj->ipv4FlowId] = newRadiusObj;
			pRadiusSession = &radiusAccountingMap[index][msgObj->ipv4FlowId];
			*found = false;
	}
	return pRadiusSession;
}

void aaaSMInterface::getSessionKey(MPacket *msgObj)
{
	if(msgObj->aaaCode == ACCESS_REQUEST || msgObj->aaaCode == ACCOUNTING_REQUEST) {

		msgObj->ipv4FlowId = (msgObj->sIp*59)^(msgObj->dIp)^(msgObj->sPort << 16)^(msgObj->dPort)^(msgObj->aaaIdentifier);
		msgObj->direction = UP;
	}
	else if(msgObj->aaaCode == ACCESS_ACCEPT || msgObj->aaaCode == ACCESS_REJECT||msgObj->aaaCode == ACCOUNTING_RESPONSE) {

		msgObj->ipv4FlowId = (msgObj->dIp*59)^(msgObj->sIp)^(msgObj->dPort << 16)^(msgObj->sPort)^(msgObj->aaaIdentifier);
		msgObj->direction = DOWN;
	}
}

void aaaSMInterface::createSession(aaaSession *pRadiusSession, MPacket *msgObj)
{
	pRadiusSession->ipVer					= msgObj->ipVer;
	pRadiusSession->StartTimeEpochSec 		= msgObj->frTimeEpochSec;
	pRadiusSession->StartTimeEpochMiliSec 	= msgObj->frTimeEpochMilliSec;
	pRadiusSession->sIp						= msgObj->sIp;
	pRadiusSession->dIp						= msgObj->dIp;
	pRadiusSession->sPort 					= msgObj->sPort;
	pRadiusSession->dPort 					= msgObj->dPort;
	pRadiusSession->reqCode 				= msgObj->aaaCode;
	pRadiusSession->protocol 				= msgObj->aaaProtocol;
	pRadiusSession->serviceType 			= msgObj->aaaServiceType;
	pRadiusSession->accStatusType 			= msgObj->accStatusType;
	pRadiusSession->accTerminationCause 	= msgObj->aaaTerminationCause;
	pRadiusSession->packetIdentifier		= msgObj->aaaIdentifier;
	pRadiusSession->accAuth					= msgObj->accAuth;
	pRadiusSession->framedIPLong			= msgObj->aaaFramedIp;
	strcpy(pRadiusSession->userName, 		msgObj->userName);


	if(msgObj->aaaCode == ACCOUNTING_REQUEST)
	{
		pRadiusSession->inputOctets 	= msgObj->inputOctets;
		pRadiusSession->outputOctets	= msgObj->outputOctets;
		pRadiusSession->inputPackets	= msgObj->inputPackets;
		pRadiusSession->outputPackets	= msgObj->outputPackets;
		pRadiusSession->inputGigaWords	= msgObj->inputGigaWords;
		pRadiusSession->outputGigaWords	= msgObj->outputGigaWords;
	}
}

void aaaSMInterface::updateSession(aaaSession *pRadiusSession, MPacket *msgObj)
{
		pRadiusSession->respCode				= msgObj->aaaCode;
		pRadiusSession->EndTimeEpochSec 		= msgObj->frTimeEpochSec;
		pRadiusSession->EndTimeEpochMiliSec 	= msgObj->frTimeEpochMilliSec;

		if(strstr(msgObj->replyMsg, "password") != NULL)
                strcpy(pRadiusSession->replyMsg, "password check failed");
        else if(strstr(msgObj->replyMsg, "account") != NULL)
                strcpy(pRadiusSession->replyMsg, "account not active");
        else if(strstr(msgObj->replyMsg, "profile") != NULL)
                strcpy(pRadiusSession->replyMsg, "user profile not found");
        else if(strstr(msgObj->replyMsg, "mac") != NULL)
                strcpy(pRadiusSession->replyMsg, "mac validation failed");
        else if(strstr(msgObj->replyMsg, "Password") != NULL)
                strcpy(pRadiusSession->replyMsg, "password check failed");
        else if(strstr(msgObj->replyMsg, "primary") != NULL)
                strcpy(pRadiusSession->replyMsg, "primary service rule not satisfied");
        else if(strstr(msgObj->replyMsg, "Welcome") != NULL)
                strcpy(pRadiusSession->replyMsg, "Welcome");
        else
                strcpy(pRadiusSession->replyMsg, msgObj->replyMsg);
}

void aaaSMInterface::eraseSession(aaaSession *pRadiusSession)
{
	switch(pRadiusSession->reqCode)
	{
	case ACCESS_REQUEST:
	case ACCESS_ACCEPT:
	case ACCESS_REJECT:
						radiusAccessMap[pRadiusSession->mapIndex].erase(pRadiusSession->aaaKey);
						break;

	case ACCOUNTING_REQUEST:
	case ACCOUNTING_RESPONSE:
						radiusAccountingMap[pRadiusSession->mapIndex].erase(pRadiusSession->aaaKey);
						break;
	}
}

void aaaSMInterface::updateGlbIPTable(aaaSession *pAaaSession)
{
	char userIpAddress[IPV6_ADDR_LEN];

	userIpAddress[0] = 0;

	/* Don't Store the User Name Having MAC Address */
	if(strstr(pAaaSession->userName, ":") != NULL || strcmp(userIpAddress , "0.0.0.0") == 0)
		return;

	long2Ip(pAaaSession->framedIPLong, userIpAddress);

	if(strlen(pAaaSession->userName) < 3)
		return;

	/* Store with User IP */
	aaaLockMap();

	switch(pAaaSession->accStatusType)
	{
		case START_STATUS_TYPE:	/* START (1) */
		{
			TheLog_nc_v2(Log::Trace, name()," START: User: %16s| IP: %16s", pAaaSession->userName, userIpAddress);

			std::map<std::string, userInfo>::iterator userIdIt = aaaGlbMap::aaaGlbUserIdMap.find(pAaaSession->userName);

			/* If we get UPDATE request first than START request */
			if(userIdIt != aaaGlbMap::aaaGlbUserIdMap.end())
			{
				TheLog_nc_v1(Log::Trace, name()," START: User: %16s found in UserId Map", pAaaSession->userName);
				if(userIdIt->second.allocatedIpLong != pAaaSession->framedIPLong)
				{
					TheLog_nc_v1(Log::Trace, name()," START: User: %16s Ip Not same, Somehow missed STOP Request", pAaaSession->userName);

					std::map<uint32_t, userInfo>::iterator userIpIt = aaaGlbMap::aaaGlbUserIpMap.find(userIdIt->second.allocatedIpLong);
					if(userIpIt != aaaGlbMap::aaaGlbUserIpMap.end())
						aaaGlbMap::aaaGlbUserIpMap.erase(userIdIt->second.allocatedIpLong);

					userInfo userinfo;

					userinfo.allocatedIpLong = pAaaSession->framedIPLong;
					userinfo.oldAllocatedIpLong = userIdIt->second.allocatedIpLong;
					strcpy(userinfo.userName, pAaaSession->userName);

					aaaGlbMap::aaaGlbUserIpMap[userinfo.allocatedIpLong] = userinfo;

					TheLog_nc_v1(Log::Trace, name()," User: %16s Updating UserId & UserIP Map", pAaaSession->userName);

					userIdIt->second.oldAllocatedIpLong = userIdIt->second.allocatedIpLong;
					userIdIt->second.allocatedIpLong = pAaaSession->framedIPLong;
					strcpy(userIdIt->second.userName, pAaaSession->userName);
				}
				else
				{
					TheLog_nc_v1(Log::Trace, name()," START: User: %16s Ip same, do noting.", pAaaSession->userName);
				}
			}
			else
			{
				TheLog_nc_v2(Log::Trace, name()," START: New User: %16s| IP: %16s", pAaaSession->userName, userIpAddress);

				userInfo userinfo;
				userinfo.oldAllocatedIpLong = 0;
				userinfo.allocatedIpLong = pAaaSession->framedIPLong;
				strcpy(userinfo.userName, pAaaSession->userName);

				aaaGlbMap::aaaGlbUserIdMap[userinfo.userName] = userinfo;

				/* Delete the data corresponding to frameIP in IPMap */
				std::map<uint32_t, userInfo>::iterator userIpIt = aaaGlbMap::aaaGlbUserIpMap.find(pAaaSession->framedIPLong);
				if(userIpIt != aaaGlbMap::aaaGlbUserIpMap.end())
					aaaGlbMap::aaaGlbUserIpMap.erase(pAaaSession->framedIPLong);

				aaaGlbMap::aaaGlbUserIpMap[userinfo.allocatedIpLong] = userinfo;
			}
		}
		break;

		case STOP_STATUS_TYPE:	/* STOP */
		{
			TheLog_nc_v1(Log::Trace, name()," STOP: User: %16s", pAaaSession->userName);
			std::map<std::string, userInfo>::iterator userIdIt = aaaGlbMap::aaaGlbUserIdMap.find(pAaaSession->userName);

			if(userIdIt != aaaGlbMap::aaaGlbUserIdMap.end())
			{
				TheLog_nc_v1(Log::Trace, name()," STOP: User: %16s found in UserId and UserIp Map Deleting.", pAaaSession->userName);

				std::map<uint32_t, userInfo>::iterator userIpIt = aaaGlbMap::aaaGlbUserIpMap.find(userIdIt->second.allocatedIpLong);

				if(userIpIt != aaaGlbMap::aaaGlbUserIpMap.end())
					aaaGlbMap::aaaGlbUserIpMap.erase(userIdIt->second.allocatedIpLong);

				aaaGlbMap::aaaGlbUserIdMap.erase(pAaaSession->userName);
			}
		}
		break;

		case UPDATE_STATUS_TYPE:	/* UPDATE */
		{
			TheLog_nc_v2(Log::Trace, name()," UPDATE: User: %16s| IP: %16s", pAaaSession->userName, userIpAddress);

			std::map<std::string, userInfo>::iterator userIdIt = aaaGlbMap::aaaGlbUserIdMap.find(pAaaSession->userName);
			if(userIdIt != aaaGlbMap::aaaGlbUserIdMap.end())
			{
				if(userIdIt->second.allocatedIpLong != pAaaSession->framedIPLong)
				{
					TheLog_nc_v1(Log::Trace, name()," UPDATE: User: %16s found in UserId Map, but allocated and frame IP are not same.", pAaaSession->userName);

					userIdIt->second.oldAllocatedIpLong = userIdIt->second.allocatedIpLong;
					userIdIt->second.allocatedIpLong = pAaaSession->framedIPLong;


					TheLog_nc_v1(Log::Trace, name()," UPDATE: User: %16s Reinitializing UserIp map.", pAaaSession->userName);

					std::map<uint32_t, userInfo>::iterator userIpIt = aaaGlbMap::aaaGlbUserIpMap.find(userIdIt->second.oldAllocatedIpLong);

					if(userIpIt != aaaGlbMap::aaaGlbUserIpMap.end())
						aaaGlbMap::aaaGlbUserIpMap.erase(userIdIt->second.oldAllocatedIpLong);

					userInfo userinfo;

					userinfo.allocatedIpLong = pAaaSession->framedIPLong;
					userinfo.oldAllocatedIpLong = userIdIt->second.oldAllocatedIpLong;

					strcpy(userinfo.userName, pAaaSession->userName);

					aaaGlbMap::aaaGlbUserIpMap[userinfo.allocatedIpLong] = userinfo;
				}
				else
				{
					TheLog_nc_v1(Log::Trace, name()," UPDATE: User: %16s found in UserId Map, allocated and frame IP are same, do noting.", pAaaSession->userName);
				}
			}
			else
			{
				TheLog_nc_v2(Log::Trace, name()," UPDATE: New User: %16s| IP: %16s", pAaaSession->userName, userIpAddress);

				userInfo userinfo;

				userinfo.oldAllocatedIpLong = 0;
				userinfo.allocatedIpLong = pAaaSession->framedIPLong;
				strcpy(userinfo.userName, pAaaSession->userName);

				aaaGlbMap::aaaGlbUserIdMap[userinfo.userName] = userinfo;

				std::map<uint32_t, userInfo>::iterator userIpIt = aaaGlbMap::aaaGlbUserIpMap.find(userinfo.allocatedIpLong);
				if(userIpIt != aaaGlbMap::aaaGlbUserIpMap.end())
					aaaGlbMap::aaaGlbUserIpMap.erase(userinfo.allocatedIpLong);

				aaaGlbMap::aaaGlbUserIpMap[userinfo.allocatedIpLong] = userinfo;
			}
		}
		break;

	default:
		break;
	}

	aaaUnLockMap();

	if(pAaaSession->ipv6AddressPrefixFlag)
	{
		/* Store with IPv6 User IP */
		aaaLockMap();

		std::map<std::string, userInfo>::iterator it = aaaGlbMap::aaaGlbIpv6UserMap.find(pAaaSession->userIpV6);

		if(it != aaaGlbMap::aaaGlbIpv6UserMap.end())
		{
			if(std::string(it->second.userName).compare(std::string(pAaaSession->userName)) == 0)
			{
			}
			else
			{
				aaaGlbMap::aaaGlbIpv6UserMap.erase(pAaaSession->userIpV6);
				userInfo userinfo;

				strcpy(userinfo.userName, pAaaSession->userName);
				aaaGlbMap::aaaGlbIpv6UserMap[pAaaSession->userIpV6] = userinfo;
			}
		}
		else
		{
			userInfo userinfo;

			strcpy(userinfo.userName, pAaaSession->userName);
			aaaGlbMap::aaaGlbIpv6UserMap[std::string(pAaaSession->userIpV6)] = userinfo;
		}
		aaaUnLockMap();
	}
}

void aaaSMInterface::aaaTimeOutCleanSession()
{
	uint32_t sessionCnt = 0, cleanCnt = 0, scanCnt = 0, accSessionCnt = 0, accoSessionCnt = 0;

	radiusStats::aaaSessionCnt[this->instanceId] 		= sessionCnt;
	radiusStats::accSessionCnt[this->instanceId] 		= accSessionCnt;
	radiusStats::accoSessionCnt[this->instanceId] 		= accoSessionCnt;
	radiusStats::aaaSessionScanned[this->instanceId] 	= scanCnt;
	radiusStats::aaaSessionCleaned[this->instanceId] 	= cleanCnt;
	radiusStats::aaaGlbUserIdCnt = 0;
	radiusStats::aaaGlbUserIpCnt = 0;

	for(uint32_t i = 0; i < AAA_SESSION_POOL_ARRAY_SIZE; i++)
	{
		accSessionCnt += radiusAccessMap[i].size();
		accoSessionCnt += radiusAccountingMap[i].size();
	}
	sessionCnt = accSessionCnt + accoSessionCnt;

	for(uint16_t i = 0; i < AAA_SESSION_POOL_ARRAY_SIZE; i++)
	{
		for(auto elem : radiusAccessMap[i])
		{
			scanCnt++ ;
			timedOutCleanSession(elem.first, &elem.second, i);
		}
	}

	radiusStats::accSessionCnt[this->instanceId] = scanCnt;
	cleanCnt += cleanUpCnt;
	eraseAccessSession();

	for(uint32_t i = 0; i < AAA_SESSION_POOL_ARRAY_SIZE; i++)
	{
		for(auto elem : radiusAccountingMap[i])
		{
			scanCnt++;
			timedOutCleanSession(elem.first, &elem.second, i);
		}
	}
	cleanCnt += cleanUpCnt;
	eraseAccountingSession();

	radiusStats::aaaSessionCnt[this->instanceId] 		= sessionCnt;
	radiusStats::accSessionCnt[this->instanceId] 		= accSessionCnt;
	radiusStats::accoSessionCnt[this->instanceId] 		= accoSessionCnt;
	radiusStats::aaaSessionScanned[this->instanceId] 	= scanCnt;
	radiusStats::aaaSessionCleaned[this->instanceId] 	= cleanCnt;

	radiusStats::aaaGlbUserIdCnt = aaaGlbMap::aaaGlbUserIdMap.size();
	radiusStats::aaaGlbUserIpCnt = aaaGlbMap::aaaGlbUserIpMap.size();
}

void aaaSMInterface::timedOutCleanSession(uint64_t key, aaaSession *pRadiusSession, uint32_t count)
{
	uint64_t curEpochSec = Global::CURRENT_EPOCH_SEC;
	bool eraseFlag = false;

	uint16_t IdleTimeSec = Global::AAA_IDLE_SESSION_TIMEOUT_IN_SEC;

	if(((pRadiusSession->StartTimeEpochSec > 0) && ((curEpochSec - pRadiusSession->StartTimeEpochSec) > IdleTimeSec)) ||
			((pRadiusSession->EndTimeEpochSec > 0) && ((curEpochSec - pRadiusSession->EndTimeEpochSec) > IdleTimeSec)))
	{
		radiusCleanMap[pRadiusSession->aaaKey] = count;
		cleanUpCnt++;
	}
}

void aaaSMInterface::eraseAccessSession()
{
	aaaSession *pRadiusSession;

	for(auto elem : radiusCleanMap)
		radiusAccessMap[elem.second].erase(elem.first);

	radiusCleanMap.clear();
	cleanUpCnt = 0;
}

void aaaSMInterface::eraseAccountingSession()
{
	aaaSession *pRadiusSession;

	for(auto elem : radiusCleanMap)
		radiusAccountingMap[elem.second].erase(elem.first);

	radiusCleanMap.clear();
	cleanUpCnt = 0;
}

void aaaSMInterface::flushRadiusSession(aaaSession *pRadiusSession, bool erase, uint16_t flushType)
{
	uint64_t epochSecNow = Global::CURRENT_EPOCH_SEC;

	pRadiusSession->flushTime = epochSecNow;
	pRadiusSession->flushType = flushType;

	uint16_t idx = PKT_WRITE_TIME_INDEX(epochSecNow , Global::TIME_INDEX);
	storeRadiusSession(idx, pRadiusSession);

	if(erase)
		eraseSession(pRadiusSession);
}

void aaaSMInterface::storeRadiusSession(uint16_t idx, aaaSession *pRadiusSession)
{
	uint16_t flusherNo = instanceId % Global::NO_OF_AAA_FLUSHER;

	flusherStore::aaa[flusherNo][instanceId][idx][flusherStore::aaaCnt[flusherNo][instanceId][idx]].copy(pRadiusSession);
	flusherStore::aaaCnt[flusherNo][instanceId][idx]++;
}
