/*
  * TCPFlusherUtility.cpp
 *
 *  Created on: Dec 21, 2016
 *      Author: Deb
 */

#include "flusherUtility.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string.h>


flusherUtility::flusherUtility(uint16_t instanceId)
{
}

flusherUtility::~flusherUtility()
{ }

void flusherUtility::lockDnsMap()
{
	pthread_mutex_lock(&mapDnsLock::lockCount);
	while (mapDnsLock::count == 0)
		pthread_cond_wait(&mapDnsLock::nonzero, &mapDnsLock::lockCount);
	mapDnsLock::count = mapDnsLock::count - 1;
	pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void flusherUtility::unLockDnsMap()
{
    pthread_mutex_lock(&mapDnsLock::lockCount);
    if (mapDnsLock::count == 0)
        pthread_cond_signal(&mapDnsLock::nonzero);
    mapDnsLock::count = mapDnsLock::count + 1;
    pthread_mutex_unlock(&mapDnsLock::lockCount);
}

void flusherUtility::lockAaaMap()
{
	    pthread_mutex_lock(&mapAaaLock::lockCount);
	    while (mapAaaLock::count == 0)
	        pthread_cond_wait(&mapAaaLock::nonzero, &mapAaaLock::lockCount);
	    mapAaaLock::count = mapAaaLock::count - 1;
	    pthread_mutex_unlock(&mapAaaLock::lockCount);
}

void flusherUtility::unAaaMap()
{
    pthread_mutex_lock(&mapAaaLock::lockCount);
    if (mapAaaLock::count == 0)
        pthread_cond_signal(&mapAaaLock::nonzero);
    mapAaaLock::count = mapAaaLock::count + 1;
    pthread_mutex_unlock(&mapAaaLock::lockCount);
}

void flusherUtility::getTcpVps(tcpSession *pIpSession, char *dnVolPerSec, char *upVolPerSec)
{
	char timeBuffer[100];
	bool printUpvps = false;
	bool printDnvps = false;
	uint32_t volume, c_pickThrPut, f_pickThrPut;
	uint32_t c_up_pickThrPut, f_up_pickThrPut, c_dn_pickThrPut, f_dn_pickThrPut;
	uint32_t upvolume, dnvolume;
	uint32_t tcpUpPacket, tcpDnPacket;
	uint16_t tcpUpCount, tcpDnCount;

	uint32_t timeDiff = 0;

	upvolume = dnvolume = 0;
	tcpUpPacket = tcpDnPacket = 0;
	tcpUpCount = tcpDnCount = 0;
	uint32_t firstSec = 0;

	int packetCount = 0;
	volume = c_pickThrPut = f_pickThrPut = 0;
	c_up_pickThrPut = f_up_pickThrPut = c_dn_pickThrPut = f_dn_pickThrPut = 0;

	for(int i = 0; i < 10000; i++)
		vpsTimeKeys[i] = 0;

//	for(auto elem : pIpSession->packTimeMap)
	for(auto elem = pIpSession->packTimeMap.begin(), next_elem = elem; elem != pIpSession->packTimeMap.end(); elem = next_elem)
	{
		++next_elem;

		packetCount ++;
		vpsTimeKeys[packetCount] = elem->first;
		volume = elem->second.totalVolume;
		upvolume = elem->second.upVolume;
		dnvolume = elem->second.dnVolume;

		c_pickThrPut = volume;
		if (c_pickThrPut > f_pickThrPut)
			f_pickThrPut = c_pickThrPut;

		if(upvolume > 0) {
			tcpUpCount += 1;
			tcpUpPacket = elem->second.upPackets;
			upvolume = elem->second.upVolume;
			c_up_pickThrPut = upvolume;
			if (c_up_pickThrPut > f_up_pickThrPut)
				f_up_pickThrPut = c_up_pickThrPut;
		}

		if(dnvolume > 0){
			tcpDnCount += 1;
			tcpDnPacket = elem->second.dnPackets;
			dnvolume = elem->second.dnVolume;
			c_dn_pickThrPut = dnvolume;
			if (c_dn_pickThrPut > f_dn_pickThrPut)
				f_dn_pickThrPut = c_dn_pickThrPut;
		}

		if(packetCount == 1 ) {
			firstSec = elem->first;
			dnVolPerSec[0] = 0;
			upVolPerSec[0] = 0;

			sprintf(dnVolPerSec, "%u=", firstSec);
			sprintf(upVolPerSec, "%u=", firstSec);
		}

		if(dnvolume > 0)
		{
			if(strlen(dnVolPerSec) < (VPS_MAX_LEN - VPS_SINGLE_ELEMENT_SIZE))
			{
				timeDiff = elem->first - firstSec;
				if(timeDiff >= 0) { // Checking the TP
					timeBuffer[0] = 0;
					sprintf(timeBuffer, "%d#%u#%u;", timeDiff, tcpDnPacket, dnvolume);	//Volume only, keep in Bytes
					strcat(dnVolPerSec, timeBuffer);
					timeBuffer[0] = 0;
					printDnvps = true;
				}
			}
		}

		if(upvolume > 0)
		{
			if(strlen(upVolPerSec) < (VPS_MAX_LEN - VPS_SINGLE_ELEMENT_SIZE))
			{
				timeDiff = elem->first - firstSec;
//				if(timeDiff >= 0 && (tcpUpPacket < IPGlobal::PACKET_PER_SEC))
				if(timeDiff >= 0)
				{
					timeBuffer[0] = 0;
					sprintf(timeBuffer, "%d#%u#%u;", timeDiff, tcpUpPacket, upvolume);	//Volume only, keep in Bytes
					strcat(upVolPerSec, timeBuffer);
					timeBuffer[0] = 0;
					printUpvps = true;
				}
			}
		}
		dnvolume = upvolume = 0;
		pIpSession->packTimeMap.erase(elem);
	}

	pIpSession->pckTotalTimeSec = tcpUpCount + tcpDnCount;

	for(int i=0; i <= packetCount; i++)
	{
		pIpSession->packTimeMap[vpsTimeKeys[i]].reset();
		pIpSession->packTimeMap.erase(vpsTimeKeys[i]);
		vpsTimeKeys[i] = 0;
	}

	pIpSession->packTimeMap.clear();

	if(tcpDnCount == 0 || printDnvps == false)
		strcpy(dnVolPerSec, "NULL");

	if(tcpUpCount == 0 || printUpvps == false)
		strcpy(upVolPerSec, "NULL");


	/* Pick Throughput / Sec */
	pIpSession->peakSessionTP 	= f_pickThrPut * 8;		//Converting to bits per second
	pIpSession->upPeakSessionTP = f_up_pickThrPut * 8;	//Converting to bits per second
	pIpSession->dnPeakSessionTP = f_dn_pickThrPut * 8;	//Converting to bits per second

	if(packetCount > 0 && pIpSession->frSize > 0)
		pIpSession->sessionTP = (pIpSession->frSize * 8) / packetCount;		//Converting to bps
	else
		pIpSession->sessionTP = 0;

	if(tcpUpPacket > 0 && pIpSession->upFrSize > 0)
		pIpSession->upSessionTP = (pIpSession->upFrSize * 8) / tcpUpCount;	//Converting to bps
	else
		pIpSession->upSessionTP = 0;

	if(tcpDnPacket > 0 && pIpSession->dnFrSize > 0)
		pIpSession->dnSessionTP = (pIpSession->dnFrSize * 8) / tcpDnCount;	//Converting to bps
	else
		pIpSession->dnSessionTP = 0;

	if(!f_dn_pickThrPut)
		pIpSession->dnPeakSessionTP = pIpSession->dnSessionTP;

	if(!f_up_pickThrPut)
		pIpSession->upPeakSessionTP = pIpSession->upSessionTP;

}

void flusherUtility::getUdpVps(udpSession *pUdpSession, char *dnVolPerSec, char *upVolPerSec)
{
	char timeBuffer[100];
	bool printUpvps = false;
	bool printDnvps = false;

	uint16_t tcpUpCount, tcpDnCount;
	uint32_t volume, c_pickThrPut, f_pickThrPut;
	uint32_t c_up_pickThrPut, f_up_pickThrPut, c_dn_pickThrPut, f_dn_pickThrPut;
	uint32_t upvolume, dnvolume;
	uint32_t tcpUpPacket, tcpDnPacket;
	uint32_t timeDiff = 0;

	upvolume = dnvolume = 0;
	tcpUpPacket = tcpDnPacket = 0;
	tcpUpCount = tcpDnCount = 0;
	uint32_t firstSec = 0;

	int packetCount = 0;
	volume = c_pickThrPut = f_pickThrPut = 0;
	c_up_pickThrPut = f_up_pickThrPut = c_dn_pickThrPut = f_dn_pickThrPut = 0;

	for(int i = 0; i < 10000; i++)
		vpsTimeKeys[i] = 0;

	for(auto elem = pUdpSession->packTimeMap.begin(), next_elem = elem; elem != pUdpSession->packTimeMap.end(); elem = next_elem)
	{
		++next_elem;

		packetCount ++;
		vpsTimeKeys[packetCount] = elem->first;
		volume = elem->second.totalVolume;
		upvolume = elem->second.upVolume;
		dnvolume = elem->second.dnVolume;

		c_pickThrPut = volume;
		if (c_pickThrPut > f_pickThrPut)
			f_pickThrPut = c_pickThrPut;

		if(upvolume > 0)
		{
			tcpUpCount += 1;
			tcpUpPacket = elem->second.upPackets;
			upvolume = elem->second.upVolume;
			c_up_pickThrPut = upvolume;

			if (c_up_pickThrPut > f_up_pickThrPut)
				f_up_pickThrPut = c_up_pickThrPut;
		}

		if(dnvolume > 0)
		{
			tcpDnCount += 1;
			tcpDnPacket = elem->second.dnPackets;
			dnvolume = elem->second.dnVolume;
			c_dn_pickThrPut = dnvolume;

			if (c_dn_pickThrPut > f_dn_pickThrPut)
				f_dn_pickThrPut = c_dn_pickThrPut;
		}

		if(packetCount == 1 )
		{
			firstSec = elem->first;
			dnVolPerSec[0] = 0;
			upVolPerSec[0] = 0;

			sprintf(dnVolPerSec, "%u=", firstSec);
			sprintf(upVolPerSec, "%u=", firstSec);
		}

		if(dnvolume > 0)
		{
			if(strlen(dnVolPerSec) < (VPS_MAX_LEN - VPS_SINGLE_ELEMENT_SIZE))
			{
				timeDiff = elem->first - firstSec;
				if(timeDiff >= 0) { // Checking the TP
					timeBuffer[0] = 0;
					sprintf(timeBuffer, "%d#%u#%u;", timeDiff, tcpDnPacket, dnvolume);	//Volume only, keep in Bytes
					strcat(dnVolPerSec, timeBuffer);
					timeBuffer[0] = 0;
					printDnvps = true;
				}
			}
		}

		if(upvolume > 0)
		{
			if(strlen(upVolPerSec) < (VPS_MAX_LEN - VPS_SINGLE_ELEMENT_SIZE))
			{
				timeDiff = elem->first - firstSec;
				if(timeDiff >= 0)
				{
					timeBuffer[0] = 0;
					sprintf(timeBuffer, "%d#%u#%u;", timeDiff, tcpUpPacket, upvolume);	//Volume only, keep in Bytes
					strcat(upVolPerSec, timeBuffer);
					timeBuffer[0] = 0;
					printUpvps = true;
				}
			}
		}
		dnvolume = upvolume = 0;
		pUdpSession->packTimeMap.erase(elem);
	}

	pUdpSession->pckTotalTimeSec = tcpUpCount + tcpDnCount;

	for(int i=0; i <= packetCount; i++)
	{
		pUdpSession->packTimeMap[vpsTimeKeys[i]].reset();
		pUdpSession->packTimeMap.erase(vpsTimeKeys[i]);
		vpsTimeKeys[i] = 0;
	}

	pUdpSession->packTimeMap.clear();

	if(tcpDnCount == 0 || printDnvps == false)
		strcpy(dnVolPerSec, "NULL");

	if(tcpUpCount == 0 || printUpvps == false)
		strcpy(upVolPerSec, "NULL");


	/* Pick Throughput / Sec */
	pUdpSession->peakSessionTP 	= f_pickThrPut * 8;		//Converting to bits per second
	pUdpSession->upPeakSessionTP = f_up_pickThrPut * 8;	//Converting to bits per second
	pUdpSession->dnPeakSessionTP = f_dn_pickThrPut * 8;	//Converting to bits per second

	if(packetCount > 0 && pUdpSession->frSize > 0)
		pUdpSession->sessionTP = (pUdpSession->frSize * 8) / packetCount;		//Converting to bps
	else
		pUdpSession->sessionTP = 0;

	if(tcpUpPacket > 0 && pUdpSession->upFrSize > 0)
		pUdpSession->upSessionTP = (pUdpSession->upFrSize * 8) / tcpUpCount;	//Converting to bps
	else
		pUdpSession->upSessionTP = 0;

	if(tcpDnPacket > 0 && pUdpSession->dnFrSize > 0)
		pUdpSession->dnSessionTP = (pUdpSession->dnFrSize * 8) / tcpDnCount;	//Converting to bps
	else
		pUdpSession->dnSessionTP = 0;

	if(!f_dn_pickThrPut)
		pUdpSession->dnPeakSessionTP = pUdpSession->dnSessionTP;

	if(!f_up_pickThrPut)
		pUdpSession->upPeakSessionTP = pUdpSession->upSessionTP;
}

void flusherUtility::buildUdpXdr(udpSession *pUdpSession, char *xdr)
{
	string sessionKey = "";
	string url = "NULL";
	char protoDesc[5];
	xdr[0] = protoDesc[0] = 0;

	char dnVolPerSec[VPS_MAX_LEN];
	char upVolPerSec[VPS_MAX_LEN];

	char userIp[IPV6_ADDR_LEN], userIdChar[IPV6_ADDR_LEN];
	userIp[0] = userIdChar[0] = 0;

	char userId[IPV6_ADDR_LEN] 	= "NA";
	char userMac[5] 			= "NA";
	char userOlt[5] 			= "NA";
	char userPlan[5] 			= "NA";
	char userPolicyPlan[5] 		= "NA";

	uint16_t jitterUp = 0;
	uint16_t jitterDn = 0;

	std::size_t found;

	/* Get Volume / Sec */
	getUdpVps(pUdpSession, dnVolPerSec, upVolPerSec);

	/* get URL */
	switch(pUdpSession->ipVer)
	{
		case IPVersion4:
		{
			sessionKey = to_string(pUdpSession->ipV4sessionKey);

			url = getResolvedIp4(pUdpSession->dIpv4);

			long2Ip(pUdpSession->sIpv4, pUdpSession->sIpv6);
			long2Ip(pUdpSession->dIpv4, pUdpSession->dIpv6);

			uint32_t ip = getIpV4UserId(pUdpSession->sIpv4, pUdpSession->dIpv4, userId);

			if(string(userId).length() == 0 || string(userId).compare("NA") == 0)
			{ long2Ip(pUdpSession->sIpv4, userId); }

			long2Ip(pUdpSession->sIpv4, userIp);

			strcpy(userOlt, "NA");

		}
		break;

		case IPVersion6:
		{
			sessionKey = pUdpSession->ipV6sessionKey;

			if(strlen(pUdpSession->sIpv6) == 0 || strlen( pUdpSession->dIpv6) == 0)
				return;

			strcpy(userId, pUdpSession->sIpv6);
			strcpy(userIp, pUdpSession->sIpv6);
			strcpy(userOlt, "NA");
		}
		break;
	}

	if((strcmp(dnVolPerSec, "NULL") == 0) && (pUdpSession->dnPLoadSize > 0)) return;
	if((strcmp(upVolPerSec, "NULL") == 0) && (pUdpSession->upPLoadSize > 0)) return;

	sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- Protocol Type,     04- Protocol Desc,
				 "%d,%s-%d,"		// 05- Dest Port,      06- Session Key,
				 "%s,%s,"			// 07- Source Mac,     08- Dest Mac,
				 "%s,%d,%s,%d,"		// 09- Source Ip,      10- Source Port,        11- Dest Ip,           12- Dest Port,
				 "%d,%d,"			// 13- VLAN Id, 	   14- Slice Counter,
				 "%d,%d,%d,"		// 15- Frame Cnt,      16- Up Frame Cnt,       17- Dn Frame Cnt,
				 "%u,%u,%u,"		// 18- Frame Size,     19- Up Frame Size,      20- Dn Frame Size,
				 "%d,%d,%d,"		// 21- Payload Pkt,    22- Up Payload Pkt,     23- Dn Payload Pkt,
				 "%u,%u,%u,"		// 24- Payload Size,   25- Up Payload Size,    26- Dn Payload Size,
				 "%lu,%lu,%d,"	// 27- Start Time,     28- End Time,           29- Pkt Total Time,
				 "%u,%u,"			// 30- Session TP,     31- Peak Session TP,
				 "%u,%u,%u,%u,"		// 32- Up Session TP,  33- Up Session Peak TP, 34- Dn Session TP,     35- Dn Session Peak TP,
				 "%u,%d,%s,%s,"		// 36- Syn Latency,	   37- Cause Code,         38- Content Type,      39- Dn Vol/Sec,
				 "%d,%lu,"			// 40- SynRcv,         41- SynRcv Nano Sec,
				 "%d,%lu,"			// 42- SynAckRcv,      43- SynAckRcv Nano Sec,
				 "%d,%lu,"			// 44- DataRcv,        45- DataRcv Nano Sec,
				 "%d,%lu,"			// 46- FinRcv,         47- FinRcv Nano Sec,
				 "%s,%s,%s,"		// 48- Up Vol/Sec,     49- App Ip, 				50- URL,
				 "%s,%s,%s,%s,%s,"	// 51- UserId,         52- User Plan,			53- User Policy	     54- User IP,     55- User Mac
				 "%d,%lu,%d,%s,%d,"	// 56- Flush Id		   57- Flush time		    58- TTL			     59- OLT		   60- Session Id
				 "%s,%d,%d,"		// 61- User-Agent	   62- JitterUp				63- JitterDn
				 "%d,%d,%d,%d,"		// 64- ReTransmission  65- layer3LoopCnt		66- duplicateCnt	 67- totalFrameCount
				 "%d,%d,%d",		// 68- ackRcv,         69- Ack Nano Sec			70- Ip version

			Global::PROBE_ID, IP_XDR_ID, pUdpSession->protocolType, initalize::protocolName[pUdpSession->protocolType].c_str(),
			pUdpSession->dPort, sessionKey.c_str(), pUdpSession->sliceCounter,
			"NA", "NA",
			pUdpSession->sIpv6, pUdpSession->sPort, pUdpSession->dIpv6, pUdpSession->dPort,
			0, pUdpSession->sliceCounter,
			pUdpSession->frCount, pUdpSession->upFrCount, pUdpSession->dnFrCount,
			pUdpSession->frSize, pUdpSession->upFrSize, pUdpSession->dnFrSize,
			pUdpSession->pLoadPkt, pUdpSession->upPLoadPkt, pUdpSession->dnPLoadPkt,
			pUdpSession->pLoadSize, pUdpSession->upPLoadSize, pUdpSession->dnPLoadSize,
			pUdpSession->startTimeEpochNanoSec, pUdpSession->endTimeEpochNanoSec, pUdpSession->pckTotalTimeSec,
			pUdpSession->sessionTP, pUdpSession->peakSessionTP,
			pUdpSession->upSessionTP, pUdpSession->upPeakSessionTP, pUdpSession->dnSessionTP, pUdpSession->dnPeakSessionTP,
			0, pUdpSession->causeCode, "NULL", dnVolPerSec,
			0, 0,
			0, 0,
			0, 0,
			0, 0,
			upVolPerSec, "0.0.0.0", url.c_str(),
			userId, userPlan, userPolicyPlan, userIp, "NA",
			pUdpSession->flushOrgId, pUdpSession->flushTime, 0, userOlt, pUdpSession->smInstanceId,
			"NA", jitterUp, jitterDn,
			0, 0, 0, pUdpSession->totalFrameCount,
			0, 0, pUdpSession->ipVer);
}

void flusherUtility::buildTcpXdr(tcpSession *pTcpSession, char *xdr)
{
	string sessionKey = "";
	string url;

	ULONG dataLatency = 0;
	ULONG sumWeightage = 0;
	char protoDesc[5];
	xdr[0] = protoDesc[0] = 0;
	bool writeXDRFlag = true;

	char dnVolPerSec[VPS_MAX_LEN];
	char upVolPerSec[VPS_MAX_LEN];

	char userIp[IPV6_ADDR_LEN];
	userIp[0] = 0;

	char userId[IPV6_ADDR_LEN] 	= "NA";
	char userMac[5] 			= "NA";
	char userOlt[5] 			= "NA";
	char userPlan[5] 			= "NA";
	char userPolicyPlan[5] 		= "NA";

	uint16_t jitterUp = 0;
	uint16_t jitterDn = 0;

	std::size_t found;

	/* Get Volume / Sec */
	getTcpVps(pTcpSession, dnVolPerSec, upVolPerSec);

	/* get URL */
	switch(pTcpSession->ipVer)
	{
		case IPVersion4:
		{
			sessionKey 	= to_string(pTcpSession->ipV4sessionKey);
			url = getResolvedIp4(pTcpSession->dIpv4);

			long2Ip(pTcpSession->sIpv4, pTcpSession->sIpv6);
			long2Ip(pTcpSession->dIpv4, pTcpSession->dIpv6);

			uint32_t ip = getIpV4UserId(pTcpSession->sIpv4, pTcpSession->dIpv4, userId);

			if(string(userId).length() == 0 || string(userId).compare("NA") == 0)
			{ long2Ip(pTcpSession->dIpv4, userId); }

			long2Ip(pTcpSession->dIpv4, userIp);
		}
		break;

		case IPVersion6:
		{
			sessionKey = pTcpSession->ipV6sessionKey;
			if(strlen(pTcpSession->sIpv6) == 0 || strlen( pTcpSession->dIpv6) == 0)
				return;

			strcpy(userId, pTcpSession->sIpv6);
			strcpy(userIp, pTcpSession->sIpv6);
		}
		break;
	}

	if(!someChecks(pTcpSession)) return;

	if((strcmp(dnVolPerSec, "NULL") == 0) && (pTcpSession->dnPLoadSize > 0)) return;
	if((strcmp(upVolPerSec, "NULL") == 0) && (pTcpSession->upPLoadSize > 0)) return;

		sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- Protocol Type,     04- Protocol Desc,
					 "%d,%s-%d,"		// 05- Dest Port,      06- Session Key,
					 "%s,%s,"			// 07- Source Mac,     08- Dest Mac,
					 "%s,%d,%s,%d,"		// 09- Source Ip,      10- Source Port,        11- Dest Ip,           12- Dest Port,
					 "%d,%d,"			// 13- VLAN Id, 	   14- Slice Counter,
					 "%d,%d,%d,"		// 15- Frame Cnt,      16- Up Frame Cnt,       17- Dn Frame Cnt,
					 "%u,%u,%u,"		// 18- Frame Size,     19- Up Frame Size,      20- Dn Frame Size,
					 "%d,%d,%d,"		// 21- Payload Pkt,    22- Up Payload Pkt,     23- Dn Payload Pkt,
					 "%u,%u,%u,"		// 24- Payload Size,   25- Up Payload Size,    26- Dn Payload Size,
					 "%lu,%lu,%d,"		// 27- Start Time,     28- End Time,           29- Pkt Total Time,
					 "%u,%u,"			// 30- Session TP,     31- Peak Session TP,
					 "%u,%u,%u,%u,"		// 32- Up Session TP,  33- Up Session Peak TP, 34- Dn Session TP,     35- Dn Session Peak TP,
					 "%u,%d,%s,%s,"		// 36- Syn Latency,	   37- Cause Code,         38- Content Type,      39- Dn Vol/Sec,
					 "%d,%lu,"			// 40- SynRcv,         41- SynRcv Nano Sec,
					 "%d,%lu,"			// 42- SynAckRcv,      43- SynAckRcv Nano Sec,
					 "%d,%lu,"			// 44- DataRcv,        45- DataRcv Nano Sec,
					 "%d,%lu,"			// 46- FinRcv,         47- FinRcv Nano Sec,
					 "%s,%s,%s,"		// 48- Up Vol/Sec,     49- App Ip, 				50- URL,
					 "%s,%s,%s,%s,%s,"	// 51- UserId,         52- User Plan,			53- User Policy	     54- User IP,     55- User Mac
					 "%d,%u,%d,%s,%d,"	// 56- Flush Id		   57- Flush time		    58- TTL			     59- OLT		   60- Session Id
					 "%s,%d,%d,"		// 61- User-Agent	   62- JitterUp				63- JitterDn
					 "%u,%u,%u,%d,"		// 64- ReTransmission  65- layer3LoopCnt		66- duplicateCnt	 67- totalFrameCount
					 "%d,%lu,%d",		// 68- ackRcv,         69- Ack Nano Sec			70- Ip version

				Global::PROBE_ID, IP_XDR_ID, pTcpSession->protocolType, initalize::protocolName[pTcpSession->protocolType].c_str(),
				pTcpSession->dPort, sessionKey.c_str(), pTcpSession->sliceCounter,
				"NA", "NA",
				pTcpSession->sIpv6, pTcpSession->sPort, pTcpSession->dIpv6, pTcpSession->dPort,
				0, pTcpSession->sliceCounter,
				pTcpSession->frCount, pTcpSession->upFrCount, pTcpSession->dnFrCount,
				pTcpSession->frSize, pTcpSession->upFrSize, pTcpSession->dnFrSize,
				pTcpSession->pLoadPkt, pTcpSession->upPLoadPkt, pTcpSession->dnPLoadPkt,
				pTcpSession->pLoadSize, pTcpSession->upPLoadSize, pTcpSession->dnPLoadSize,
				pTcpSession->startTimeEpochNanoSec, pTcpSession->endTimeEpochNanoSec, pTcpSession->pckTotalTimeSec,
				pTcpSession->sessionTP, pTcpSession->peakSessionTP,
				pTcpSession->upSessionTP, pTcpSession->upPeakSessionTP, pTcpSession->dnSessionTP, pTcpSession->dnPeakSessionTP,
				0, pTcpSession->causeCode, "NULL", dnVolPerSec,
				pTcpSession->synRcv, pTcpSession->synTimeEpochNanoSec,
				pTcpSession->synAckRcv, pTcpSession->synAckTimeEpochNanoSec,
				pTcpSession->dataRcv, pTcpSession->firstDataTimeEpochNanoSec,
				pTcpSession->finRcv, pTcpSession->finTimeEpochNanoSec,
				upVolPerSec, "0.0.0.0", url.c_str(),
				userId, userPlan, userPolicyPlan, userIp, userMac,
				pTcpSession->flushOrgId, pTcpSession->flushTime, pTcpSession->TTL, userOlt, pTcpSession->smInstanceId,
				"NA", jitterUp, jitterDn,
				pTcpSession->reTransmissionCnt, pTcpSession->layer3LoopCnt, pTcpSession->duplicateCnt, pTcpSession->totalFrameCount,
				pTcpSession->ackRcv, pTcpSession->ackTimeEpochNanoSec, pTcpSession->ipVer);

}

bool flusherUtility::someChecks(tcpSession *pIpSession)
{
	bool xdrProcess = true;

	/* These Checkes are for Spike in TP */
	if(pIpSession->frSize < pIpSession->pLoadSize)
	{
		xdrProcess = false;
		return xdrProcess;
	}

	if(pIpSession->protocolType == PACKET_IPPROTO_TCP)
	{
		if(!pIpSession->synRcv)
		{
			pIpSession->synRcv = true;
			pIpSession->synTimeEpochNanoSec = pIpSession->startTimeEpochNanoSec;
		}

		if((pIpSession->synAckRcv) && (!pIpSession->ackRcv))
		{
			pIpSession->ackRcv = true;
			pIpSession->ackTimeEpochNanoSec = pIpSession->synAckTimeEpochNanoSec + 10;
		}
		else if((!pIpSession->synAckRcv) && (pIpSession->ackRcv))
		{
			pIpSession->synAckRcv = true;
			pIpSession->synAckTimeEpochNanoSec = pIpSession->synTimeEpochNanoSec + 10;
		}
		else if((!pIpSession->synAckRcv) && (!pIpSession->ackRcv))
		{
			pIpSession->synAckRcv = true;
			pIpSession->synAckTimeEpochNanoSec = pIpSession->synTimeEpochNanoSec + 10;
			pIpSession->ackRcv = true;
			pIpSession->ackTimeEpochNanoSec = pIpSession->synAckTimeEpochNanoSec + 10;
		}

		if(pIpSession->dataRcv)
			swap4(&pIpSession->synTimeEpochNanoSec, &pIpSession->synAckTimeEpochNanoSec, &pIpSession->ackTimeEpochNanoSec, &pIpSession->firstDataTimeEpochNanoSec);
		else
			swap3(&pIpSession->synTimeEpochNanoSec, &pIpSession->synAckTimeEpochNanoSec, &pIpSession->ackTimeEpochNanoSec);

		}
	return xdrProcess;
}

void flusherUtility::swap3(uint64_t *a, uint64_t *b, uint64_t *c)
{
	uint64_t lr, mi, sm;

	if(*a > *b)
	{
		mi = *a;
		sm = *b;
	}
	else
	{
		mi = *b;
		sm = *a;
	}

	if(mi > *c)
	{
		lr = mi;
		if(sm > *c)
		{
			mi = sm;
			sm = *c;
		}
		else
		{
			mi = *c;
		}
	}
	else
		lr = *c;

	*a = sm;
	*b = mi;
	*c = lr;
}

void flusherUtility::swap4(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
	uint64_t temp = 0; ;

	if(*a > *b)
	{
		temp = *a;
		*a = *b;
		*b = temp;
	}
	if(*c > *d)
	{
		temp = *c;
		*c = *d;
		*d = temp;
	}
	if(*a > *c)
	{
		temp = *a;
		*a = *c;
		*c = temp;
	}
	if(*b > *d)
	{
		temp = *b;
		*b = *d;
		*d = temp;
	}
	if(*b > *c)
	{
		temp = *b;
		*b = *c;
		*c = temp;
	}
}

uint32_t flusherUtility::getIpV4UserId(uint32_t sourceIP, uint32_t destIP, char* userId)
{
	uint32_t userIp = 0;

	/* Get User Name against User IP */
	lockAaaMap();

	std::map<uint32_t, userInfo>::iterator it = aaaGlbMap::aaaGlbUserIpMap.find(sourceIP);
	if(it != aaaGlbMap::aaaGlbUserIpMap.end())
	{
		userIp 		= (uint32_t)it->first;
		strcpy(userId, it->second.userName);
	}
	unAaaMap();

	return userIp;
}

void flusherUtility::getipV6UserId(char *sourceIP, char *destIP, char* userId)
{
	lockAaaMap();

	if(strlen(sourceIP) < 16)
		return;

	std::map<std::string, userInfo>::iterator it = aaaGlbMap::aaaGlbIpv6UserMap.find(std::string(sourceIP).substr(0, IPV6_PREFIX_LAN));

	if(it != aaaGlbMap::aaaGlbIpv6UserMap.end())
		 strcpy(userId, it->second.userName);

	unAaaMap();
}

void flusherUtility::buildDnsXdr(dnsSession *pDnsSession, char *csvXDR)
{
	uint32_t dnsResTimeMilliSec = 0;
	string sessionKey = "";

	uint64_t sTime = pDnsSession->queryStartEpochNanoSec;
	uint64_t eTime = pDnsSession->queryEndEpochNanoSec;

	csvXDR[0] = 0;

	if(eTime > 0 && sTime > 0 && (eTime > sTime)) {
		if(sTime > 1000000) {
			sTime = sTime / (1000 * 1000);
			if(eTime > 1000000) {
				eTime = eTime / (1000 * 1000);
				dnsResTimeMilliSec = (uint32_t) (eTime - sTime);
			}
		}
	}

	switch(pDnsSession->ipVer)
	{
		case IPVersion4:
						sessionKey = to_string(pDnsSession->dnsSessionV4Key);
						/* Change Source and Destination IP Long to dotted IP */
						long2Ip(pDnsSession->sIpv4, pDnsSession->sIpv6);
						long2Ip(pDnsSession->dIpv4, pDnsSession->dIpv6);
						break;

		case IPVersion6:
						sessionKey = pDnsSession->dnsSessionV6Key;
						/* Change Source and Destination IP Long to dotted IP */
						break;
	}

	if(strlen(pDnsSession->URL) == 0)
		strcpy(pDnsSession->URL, "NA");

	if(strstr(pDnsSession->errorDesc, "No Error") != NULL)
		pDnsSession->errorCode = 0;

	sprintf(csvXDR, "%d,%d,17,DNS,"			// 1- Probe Id			2- XDR Id		3- UDP				4-  DNS
					"%s,%s,%d,%s,%d,"		// 5- User Id			6- Source Ip	7- Source Port		8-  Dest Ip		9- Dest Port
					"%s,%d,%s,"				// 10- URL				11- Error Code	12- Error Desc
					"%s,"					// 13- Address
					"%lu,%lu,%u,%s,"		// 14- Start time		15- End Time	16- Resolve Time    17- OLT
					"%s,%s,%s,%d,%s",		// 18- User Policy		19- User Plan	20- User Mac		21- Flush Type
					Global::PROBE_ID, DNS_XDR_ID,
					pDnsSession->sIpv6, pDnsSession->sIpv6, pDnsSession->sourcePort, pDnsSession->dIpv6, pDnsSession->destPort,
					pDnsSession->URL, pDnsSession->errorCode, pDnsSession->errorDesc,
					"NA",
					pDnsSession->queryStartEpochNanoSec, pDnsSession->queryEndEpochNanoSec, dnsResTimeMilliSec, "NA",
					"NA", "NA", "NA", pDnsSession->flushType, sessionKey.c_str());
}

string flusherUtility::getResolvedIp4(uint32_t dIp)
{
	lockDnsMap();
	std::string URL = findDns(dIp);
	unLockDnsMap();

	if(!URL.length())
		return("NULL");
	else
		return(URL);
}

string flusherUtility::findDns(uint32_t dIp)
{ return(getURLLookUp(dIp, DNSGlobal::dnsLookUpMap[dIp % 10])); }

string flusherUtility::getURLLookUp(uint32_t ip, std::map<uint32_t, std::string> &dnsMap)
{
	std::map<uint32_t, std::string>::iterator itSp = dnsMap.find(ip);

	if(itSp != dnsMap.end())
		return(itSp->second);

	return "";
}





void flusherUtility::formateIPv6(char *buffer)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int domain = AF_INET6, ret;


	ret = inet_pton(domain, buffer, buf);
	if (ret <= 0)
	{
		if (ret == 0) {
			fprintf(stderr, "Not in presentation format");
		}
		else
			perror("inet_pton");
	}

	if (inet_ntop(domain, buf, buffer, INET6_ADDRSTRLEN) == NULL) {
	               perror("inet_ntop");
	}
}
