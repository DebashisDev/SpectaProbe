/*
 * TCPUDPGlobal.h
 *
 *  Created on: 15-Jul-2016
 *      Author: Debashis
 */

#ifndef PLUGINS_TCP_INC_SMGLOBAL_H_
#define PLUGINS_TCP_INC_SMGLOBAL_H_


#include <map>
#include <unordered_map>

#include "IPGlobal.h"
#include "SpectaTypedef.h"

using namespace std;

#define DNS_HDR_LEN		12
#define	STUN_PORT		3478
#define UDP_NO_ERROR	0

#define IP_POOL_ARRAY_ELEMENTS			100		//Poosible values 10, 100, 1000, 10000, 100000....

#define IP_FLUSH_POOL_ARRAY_ELEMENTS	100		//Poosible values 10, 100, 1000, 10000, 100000....
#define IP_FLUSH_POOL_ARRAY_SIZE		5000

#define DNS_FLUSH_POOL_ARRAY_ELEMENTS	100		//Poosible values 10, 100, 1000, 10000, 100000....
#define DNS_FLUSH_POOL_ARRAY_SIZE		3000

#define DIAMETER_SEQ_ID	263

typedef enum {
    CHANGE_CIPHER_SPEC 	= 20,
	ALERT 				= 21,
	HANDSHAKE 			= 22,
    APP_DATA 			= 23
}TLSContentType;

typedef struct _dnsV6Url{
	int		pckLastTimeEpcohSec;
	char 	URL[URL_LEN];
	char 	address[IPV6_ADDR_LEN];

	_dnsV6Url()
	{
		pckLastTimeEpcohSec = 0;
		URL[0] = 0;
		address[0] = 0;
	}
}dnsV6Url;

typedef struct _fData
{
	uint32_t totalVolume;
	uint32_t upPackets;
	uint32_t upVolume;
	uint32_t dnPackets;
	uint32_t dnVolume;

    _fData()
	{ reset(); }

    void reset()
    {
    	totalVolume = 0;
    	upPackets = 0;
    	upVolume = 0;
    	dnPackets = 0;
    	dnVolume = 0;
    }
}fData;

typedef struct _dupInfo
{
	uint16_t ipId;
	uint8_t  ttl;
	uint8_t	direction;
	_dupInfo()
	{ reset(); }

    void reset()
    {
    	ipId = 0;
    	ttl = 0;
    	direction = 0;
    }
}dupInfo;

typedef struct _dnsSession
{
	uint8_t		ipVer;
	uint8_t		errorCode;
	uint16_t	sourcePort;
	uint16_t	destPort;
	uint16_t	state;
	uint16_t	flushType;
	uint32_t	transactionId;
	uint32_t 	sIpv4;
	uint32_t 	dIpv4;
	uint32_t	causeCode;
	uint32_t	poolIndex;
	uint64_t 	queryStartEpochSec;
	uint64_t	queryEndEpochSec;
	uint64_t 	queryStartEpochNanoSec;
	uint64_t	queryEndEpochNanoSec;
	uint64_t	dnsSessionV4Key;
	char		sIpv6[IPV6_ADDR_LEN];
	char		dIpv6[IPV6_ADDR_LEN];
	char 		URL[URL_LEN];
	char 		errorDesc[DESC_LEN];
	string		dnsSessionV6Key;

	_dnsSession()
	{ reset(); }

	void set(const _dnsSession *obj)
	{
		this->ipVer = obj->ipVer;
		this->transactionId = obj->transactionId;

		this->sourcePort = obj->sourcePort;
		this->destPort = obj->destPort;

		this->queryStartEpochSec = obj->queryStartEpochSec;
		this->queryEndEpochSec = obj->queryEndEpochSec;
		this->queryStartEpochNanoSec = obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec = obj->queryEndEpochNanoSec;

		this->sIpv4 = obj->sIpv4;
		this->dIpv4 = obj->dIpv4;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);

		strcpy(this->URL, obj->URL);

		this->causeCode = obj->causeCode;
		this->errorCode = obj->errorCode;
		strcpy(this->errorDesc, obj->errorDesc);
		this->state	= obj->state;
		this->dnsSessionV4Key = obj->dnsSessionV4Key;
		this->dnsSessionV6Key = obj->dnsSessionV6Key;
		this->flushType = obj->flushType;
		this->poolIndex = obj->poolIndex;
	}

	void copy(const _dnsSession* obj)
	{
		this->ipVer = obj->ipVer;
		this->transactionId = obj->transactionId;

		this->sourcePort = obj->sourcePort;
		this->destPort = obj->destPort;

		this->queryStartEpochSec = obj->queryStartEpochSec;
		this->queryEndEpochSec = obj->queryEndEpochSec;
		this->queryStartEpochNanoSec = obj->queryStartEpochNanoSec;
		this->queryEndEpochNanoSec = obj->queryEndEpochNanoSec;

		this->sIpv4 = obj->sIpv4;
		this->dIpv4 = obj->dIpv4;
		strcpy(this->sIpv6, obj->sIpv6);
		strcpy(this->dIpv6, obj->dIpv6);

		strcpy(this->URL, obj->URL);

		this->causeCode = obj->causeCode;
		this->errorCode = obj->errorCode;
		strcpy(this->errorDesc, obj->errorDesc);
		this->state = obj->state;
		this->dnsSessionV4Key = obj->dnsSessionV4Key;
		this->dnsSessionV6Key = obj->dnsSessionV6Key;
		this->flushType = obj->flushType;
		this->poolIndex = obj->poolIndex;
	}
	void reset()
	{
		ipVer = 0;
		transactionId = 0;

	    sourcePort = 0;
		destPort = 0;

		queryStartEpochSec = 0;
		queryEndEpochSec = 0;
		queryStartEpochNanoSec = 0;
		queryEndEpochNanoSec = 0;

		sIpv4 = 0;
		dIpv4 = 0;
		sIpv6[0] = 0;
		dIpv6[0] = 0;
		URL[0] = 0;

		causeCode = 0;
		errorCode = 0;
		errorDesc[0] = 0;
		state = -1;
		dnsSessionV4Key = 0;
		dnsSessionV6Key.clear();
		flushType = 0;
		poolIndex = 0;
	}
}dnsSession;

typedef struct _tcpSession
{
    bool		synRcv;
    bool		synAckRcv;
    bool		ackRcv;
    bool		dataRcv;
    bool		finRcv;
    bool		firstDataFlag;
	bool		activeState;
    uint8_t 	TTL;
    uint8_t		ipVer;
    uint8_t		isUpDir;
	uint8_t		causeCode;
	uint8_t		protocolType;
    uint16_t 	state;
    uint16_t 	sPort;
    uint16_t 	dPort;
    uint16_t 	pLoadPkt;
    uint16_t 	upPLoadPkt;
    uint16_t 	dnPLoadPkt;
    uint16_t 	totalFrameCount;
    uint16_t 	frCount;
    uint16_t 	upFrCount;
    uint16_t 	dnFrCount;
    uint16_t 	sliceCounter;
    uint16_t 	pckTotalTimeSec;
    uint16_t	flushOrgId;
	uint16_t	smInstanceId;
    uint32_t	sIpv4;
    uint32_t	dIpv4;
    uint32_t	pLoadSize;
    uint32_t	upPLoadSize;
    uint32_t	dnPLoadSize;
    uint32_t	frSize;
    uint32_t	upFrSize;
    uint32_t	dnFrSize;
    uint32_t 	sessionTP;
    uint32_t	peakSessionTP;
    uint32_t 	upSessionTP;
    uint32_t 	dnSessionTP;
    uint32_t	upPeakSessionTP;
    uint32_t 	dnPeakSessionTP;
    uint32_t	mapIndex;
    uint32_t	poolIndex;
	uint32_t	reTransmissionCnt;
	uint32_t	layer3LoopCnt;
	uint32_t	duplicateCnt;
    uint64_t 	pckArivalTimeEpochSec;
    uint64_t 	pckLastTimeEpochSec;
    uint64_t 	pckLastTimeEpochNanoSec;
    uint64_t	startTimeEpochSec;
    uint64_t 	startTimeEpochNanoSec;
    uint64_t	endTimeEpochNanoSec;
	uint64_t	ipV4sessionKey;
	uint64_t	synTimeEpochNanoSec;
	uint64_t	synAckTimeEpochNanoSec;
	uint64_t	ackTimeEpochNanoSec;
	uint64_t	finTimeEpochNanoSec;
    uint64_t	firstDataTimeEpochNanoSec;
	uint64_t 	flushTime;
	uint64_t 	lastActivityTimeEpohSec;
    char		sIpv6[IPV6_ADDR_LEN];
    char		dIpv6[IPV6_ADDR_LEN];
	std::string ipV6sessionKey;
	std::map<uint64_t, fData> packTimeMap;		//EpochTimeSec & fData
	std::map<uint32_t, dupInfo> dupMap;

	~_tcpSession(){}

	_tcpSession()
	{ reset(); }

	void reset()
	{
	    state = 0;
	    TTL = 0;
	    ipVer = 0;
	    sPort = 0;
	    dPort = 0;

	    sIpv4 = 0;
	    dIpv4 = 0;

	    isUpDir=0;
	    pckTotalTimeSec = 0;

	    pLoadPkt = 0;
	    upPLoadPkt = 0;
	    dnPLoadPkt = 0;

	    pLoadSize = 0;
	    upPLoadSize = 0;
	    dnPLoadSize = 0;

	    totalFrameCount = 0;
	    frCount = 0;
	    upFrCount = 0;
	    dnFrCount = 0;

	    frSize = 0;
	    upFrSize = 0;
	    dnFrSize = 0;

	    sliceCounter = 0;

	    pckArivalTimeEpochSec = 0;
	    pckLastTimeEpochSec = 0;
	    pckLastTimeEpochNanoSec = 0;

	    startTimeEpochSec = 0;
	    startTimeEpochNanoSec = 0;
	    endTimeEpochNanoSec = 0;

	    sIpv6[0] = 0;
	    dIpv6[0] = 0;

	    synRcv = false;
	    synAckRcv = false;
	    ackRcv = false;
	    dataRcv = false;
	    finRcv = false;

		sessionTP = 0;
		peakSessionTP = 0;
		upSessionTP = 0;
		dnSessionTP = 0;
		upPeakSessionTP = 0;
		dnPeakSessionTP = 0;

		causeCode = 0;
		protocolType = 0;
		ipV4sessionKey = 0;
		ipV6sessionKey.clear();

		packTimeMap.clear();
		dupMap.clear();

	    synTimeEpochNanoSec = 0;
	    synAckTimeEpochNanoSec = 0;
	    ackTimeEpochNanoSec = 0;
	    finTimeEpochNanoSec = 0;
	    firstDataFlag = false;
	    firstDataTimeEpochNanoSec = 0;

		flushOrgId = 0;
		flushTime = 0;
		lastActivityTimeEpohSec = 0;
		activeState = false;
		smInstanceId = 0;

		reTransmissionCnt = 0;
		layer3LoopCnt = 0;
		duplicateCnt = 0;
	}

	void reuse()
	{
		this->packTimeMap.clear();
		this->dupMap.clear();

		this->totalFrameCount 	= 0;
		this->frCount 		= 0;
		this->upFrCount 		= 0;
		this->dnFrCount 		= 0;

		this->frSize 		= 0;
		this->upFrSize 		= 0;
		this->dnFrSize 		= 0;

		this->pLoadPkt 	= 0;
		this->upPLoadPkt	= 0;
		this->dnPLoadPkt	= 0;

		this->pLoadSize 		= 0;
		this->upPLoadSize 	= 0;
		this->dnPLoadSize 	= 0;

		this->pckArivalTimeEpochSec = 0;
		this->startTimeEpochSec = pckLastTimeEpochSec;
		this->startTimeEpochNanoSec = pckLastTimeEpochNanoSec;

		this->endTimeEpochNanoSec = pckLastTimeEpochNanoSec;

		this->pckTotalTimeSec 	= 0;
		this->sessionTP 		= 0;
		this->peakSessionTP 	= 0;

		this->upSessionTP 		= 0;
		this->upPeakSessionTP	= 0;
		this->dnSessionTP 		= 0;
		this->dnPeakSessionTP	= 0;

		this->pckLastTimeEpochSec 		= 0;
		this->pckLastTimeEpochNanoSec 	= 0;

		this->reTransmissionCnt = 0;
		this->layer3LoopCnt 	= 0;
		this->duplicateCnt 		= 0;
	}

	_tcpSession(const _tcpSession& obj)
	{
	    this->state = obj.state;
	    this->TTL = obj.TTL;
	    this->ipVer = obj.ipVer;
	    this->sPort = obj.sPort;
	    this->dPort = obj.dPort;

	    this->sIpv4 = obj.sIpv4;
	    this->dIpv4 = obj.dIpv4;

	    this->isUpDir = obj.isUpDir;
	    this->pckTotalTimeSec = obj.pckTotalTimeSec;

	    this->pLoadPkt = obj.pLoadPkt;
	    this->upPLoadPkt = obj.upPLoadPkt;
	    this->dnPLoadPkt = obj.dnPLoadPkt;

	    this->pLoadSize = obj.pLoadSize;
	    this->upPLoadSize = obj.upPLoadSize;
	    this->dnPLoadSize = obj.dnPLoadSize;

	    this->totalFrameCount = obj.totalFrameCount;
	    this->frCount = obj.frCount;
	    this->upFrCount = obj.upFrCount;
	    this->dnFrCount = obj.dnFrCount;

	    this->frSize = obj.frSize;
	    this->upFrSize = obj.upFrSize;
	    this->dnFrSize = obj.dnFrSize;

	    this->sliceCounter = obj.sliceCounter;

	    this->pckArivalTimeEpochSec = obj.pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec = obj.pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec = obj.pckLastTimeEpochNanoSec;
	    this->startTimeEpochNanoSec = obj.startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec = obj.endTimeEpochNanoSec;
	    this->startTimeEpochSec = obj.startTimeEpochSec;

	    strcpy(this->sIpv6, obj.sIpv6);
	    strcpy(this->dIpv6, obj.dIpv6);

	    this->synRcv = obj.synRcv;
	    this->synAckRcv = obj.synAckRcv;
	    this->ackRcv = obj.ackRcv;
	    this->dataRcv = obj.dataRcv;
	    this->finRcv = obj.finRcv;

	    this->sessionTP = obj.sessionTP;
	    this->peakSessionTP = obj.peakSessionTP;
	    this->upSessionTP = obj.upSessionTP;
	    this->dnSessionTP = obj.dnSessionTP;
	    this->upPeakSessionTP = obj.upPeakSessionTP;
	    this->dnPeakSessionTP = obj.dnPeakSessionTP;

	    this->causeCode = obj.causeCode;
	    this->protocolType = obj.protocolType;
	    this->ipV4sessionKey = obj.ipV4sessionKey;
	    this->ipV6sessionKey = obj.ipV6sessionKey;

	    packTimeMap = obj.packTimeMap;
	    dupMap = obj.dupMap;

	    this->synTimeEpochNanoSec = obj.synTimeEpochNanoSec;
	    this->synAckTimeEpochNanoSec = obj.synAckTimeEpochNanoSec;
	    this->ackTimeEpochNanoSec = obj.ackTimeEpochNanoSec;
	    this->finTimeEpochNanoSec = obj.finTimeEpochNanoSec;
	    this->firstDataFlag = obj.firstDataFlag;
	    this->firstDataTimeEpochNanoSec = obj.firstDataTimeEpochNanoSec;

	    this->mapIndex = obj.mapIndex;
	    this->poolIndex = obj.poolIndex;

		this->flushOrgId = obj.flushOrgId;
		this->flushTime = obj.flushTime;
		this->lastActivityTimeEpohSec = obj.lastActivityTimeEpohSec;
		this->activeState = obj.activeState;
		this->smInstanceId = obj.smInstanceId;

		this->reTransmissionCnt = obj.reTransmissionCnt;
		this->layer3LoopCnt = obj.layer3LoopCnt;
		this->duplicateCnt = obj.duplicateCnt;
	}

	void copy(const _tcpSession* obj)
	{
		state = obj->state;
		TTL = obj->TTL;
		ipVer = obj->ipVer;
	    sPort = obj->sPort;
	    dPort = obj->dPort;

	    sIpv4 = obj->sIpv4;
	    dIpv4 = obj->dIpv4;

	    isUpDir = obj->isUpDir;
	    pckTotalTimeSec = obj->pckTotalTimeSec;

	    pLoadPkt = obj->pLoadPkt;
	    upPLoadPkt = obj->upPLoadPkt;
	    dnPLoadPkt = obj->dnPLoadPkt;

	    pLoadSize = obj->pLoadSize;
	    upPLoadSize = obj->upPLoadSize;
	    dnPLoadSize = obj->dnPLoadSize;

	    totalFrameCount = obj->totalFrameCount;

	    frCount = obj->frCount;
	    upFrCount = obj->upFrCount;
	    dnFrCount = obj->dnFrCount;

	    frSize = obj->frSize;
	    upFrSize = obj->upFrSize;
	    dnFrSize = obj->dnFrSize;

	    sliceCounter = obj->sliceCounter;

	    pckArivalTimeEpochSec = obj->pckArivalTimeEpochSec;
	    pckLastTimeEpochSec = obj->pckLastTimeEpochSec;
	    pckLastTimeEpochNanoSec = obj->pckLastTimeEpochNanoSec;
	    startTimeEpochNanoSec = obj->startTimeEpochNanoSec;
	    endTimeEpochNanoSec = obj->endTimeEpochNanoSec;
	    startTimeEpochSec = obj->startTimeEpochSec;

	    strcpy(sIpv6, obj->sIpv6);
	    strcpy(dIpv6, obj->dIpv6);

	    synRcv = obj->synRcv;
	    synAckRcv = obj->synAckRcv;
	    ackRcv = obj->ackRcv;
	    dataRcv = obj->dataRcv;
	    finRcv = obj->finRcv;

	    sessionTP = obj->sessionTP;
	    peakSessionTP = obj->peakSessionTP;
	    upSessionTP = obj->upSessionTP;
	    dnSessionTP = obj->dnSessionTP;
	    upPeakSessionTP = obj->upPeakSessionTP;
	    dnPeakSessionTP = obj->dnPeakSessionTP;

	    causeCode = obj->causeCode;
	    protocolType = obj->protocolType;
	    ipV4sessionKey = obj->ipV4sessionKey;
	    ipV6sessionKey = obj->ipV6sessionKey;

	    packTimeMap = obj->packTimeMap;
	    dupMap = obj->dupMap;

	    synTimeEpochNanoSec = obj->synTimeEpochNanoSec;
	    synAckTimeEpochNanoSec = obj->synAckTimeEpochNanoSec;
	    ackTimeEpochNanoSec = obj->ackTimeEpochNanoSec;
	    finTimeEpochNanoSec = obj->finTimeEpochNanoSec;
	    firstDataFlag = obj->firstDataFlag;
	    firstDataTimeEpochNanoSec = obj->firstDataTimeEpochNanoSec;

	    mapIndex = obj->mapIndex;
	    poolIndex = obj->poolIndex;

		flushOrgId = obj->flushOrgId;
		flushTime = obj->flushTime;
		lastActivityTimeEpohSec = obj->lastActivityTimeEpohSec;
		activeState = obj->activeState;
		smInstanceId = obj->smInstanceId;

		reTransmissionCnt = obj->reTransmissionCnt;
		layer3LoopCnt = obj->layer3LoopCnt;
		duplicateCnt = obj->duplicateCnt;
	}

}tcpSession;

typedef struct _udpSession
{
	bool		activeState;
    uint8_t		ipVer;
    uint8_t 	sliceCounter;
    uint8_t		isUpDir;
	uint8_t		causeCode;
	uint8_t		protocolType;
    uint16_t 	state;
    uint16_t 	sPort;
    uint16_t 	dPort;
    uint16_t 	pLoadPkt;
    uint16_t 	upPLoadPkt;
    uint16_t 	dnPLoadPkt;
    uint16_t 	totalFrameCount;
    uint16_t 	frCount;
    uint16_t 	upFrCount;
    uint16_t 	dnFrCount;
    uint16_t 	pckTotalTimeSec;
	uint16_t	smInstanceId;
	uint16_t	flushOrgId;
    uint32_t	sIpv4;
    uint32_t	dIpv4;
    uint32_t	pLoadSize;
    uint32_t	upPLoadSize;
    uint32_t	dnPLoadSize;
    uint32_t	frSize;
    uint32_t	upFrSize;
    uint32_t	dnFrSize;
    uint32_t 	sessionTP;
    uint32_t	peakSessionTP;
    uint32_t 	upSessionTP;
    uint32_t 	dnSessionTP;
    uint32_t	upPeakSessionTP;
    uint32_t 	dnPeakSessionTP;
	uint32_t	mapIndex;
	uint32_t	poolIndex;
    uint64_t 	pckArivalTimeEpochSec;
    uint64_t 	pckLastTimeEpochSec;
    uint64_t 	pckLastTimeEpochNanoSec;
    uint64_t	startTimeEpochSec;
    uint64_t 	startTimeEpochNanoSec;
    uint64_t	endTimeEpochNanoSec;
	uint64_t	ipV4sessionKey;
	uint64_t 	flushTime;
	uint64_t 	lastActivityTimeEpohSec;
    char		sIpv6[IPV6_ADDR_LEN];
    char		dIpv6[IPV6_ADDR_LEN];
	std::string ipV6sessionKey;
	std::map<uint64_t, fData> packTimeMap;		//EpochTimeSec & fData

	~_udpSession(){}

	_udpSession()
	{ reset(); }

	void reset()
	{
	    state = 0;
	    ipVer = 0;
	    sPort = 0;
	    dPort = 0;

	    sIpv4 = 0;
	    dIpv4 = 0;

	    isUpDir=0;
	    pckTotalTimeSec = 0;

	    pLoadPkt = 0;
	    upPLoadPkt = 0;
	    dnPLoadPkt = 0;

	    pLoadSize = 0;
	    upPLoadSize = 0;
	    dnPLoadSize = 0;

	    totalFrameCount = 0;
	    frCount = 0;
	    upFrCount = 0;
	    dnFrCount = 0;

	    frSize = 0;
	    upFrSize = 0;
	    dnFrSize = 0;

	    sliceCounter = 0;

	    pckArivalTimeEpochSec = 0;
	    pckLastTimeEpochSec = 0;
	    pckLastTimeEpochNanoSec = 0;

	    startTimeEpochSec = 0;
	    startTimeEpochNanoSec = 0;
	    endTimeEpochNanoSec = 0;

	    sIpv6[0] = 0;
	    dIpv6[0] = 0;

		sessionTP = 0;
		peakSessionTP = 0;
		upSessionTP = 0;
		dnSessionTP = 0;
		upPeakSessionTP = 0;
		dnPeakSessionTP = 0;

		causeCode = 0;
		protocolType = 0;
		ipV4sessionKey = 0;
		ipV6sessionKey.clear();

		packTimeMap.clear();

		flushOrgId = 0;
		flushTime = 0;
		lastActivityTimeEpohSec = 0;
		activeState = false;
		smInstanceId = 0;
	}

	void reuse()
	{
		this->packTimeMap.clear();

		this->totalFrameCount 	= 0;
		this->frCount 		= 0;
		this->upFrCount 		= 0;
		this->dnFrCount 		= 0;

		this->frSize 		= 0;
		this->upFrSize 		= 0;
		this->dnFrSize 		= 0;

		this->pLoadPkt 	= 0;
		this->upPLoadPkt	= 0;
		this->dnPLoadPkt	= 0;

		this->pLoadSize 		= 0;
		this->upPLoadSize 	= 0;
		this->dnPLoadSize 	= 0;

		this->pckArivalTimeEpochSec = 0;
		this->startTimeEpochSec = pckLastTimeEpochSec;
		this->startTimeEpochNanoSec = pckLastTimeEpochNanoSec;

		this->endTimeEpochNanoSec = pckLastTimeEpochNanoSec;

		this->pckTotalTimeSec 	= 0;
		this->sessionTP 		= 0;
		this->peakSessionTP 	= 0;

		this->upSessionTP 		= 0;
		this->upPeakSessionTP	= 0;
		this->dnSessionTP 		= 0;
		this->dnPeakSessionTP	= 0;

		this->pckLastTimeEpochSec 		= 0;
		this->pckLastTimeEpochNanoSec 	= 0;
	}

	_udpSession(const _udpSession& obj)
	{
	    this->state = obj.state;
	    this->ipVer = obj.ipVer;
	    this->sPort = obj.sPort;
	    this->dPort = obj.dPort;

	    this->sIpv4 = obj.sIpv4;
	    this->dIpv4 = obj.dIpv4;

	    this->isUpDir = obj.isUpDir;
	    this->pckTotalTimeSec = obj.pckTotalTimeSec;

	    this->pLoadPkt = obj.pLoadPkt;
	    this->upPLoadPkt = obj.upPLoadPkt;
	    this->dnPLoadPkt = obj.dnPLoadPkt;

	    this->pLoadSize = obj.pLoadSize;
	    this->upPLoadSize = obj.upPLoadSize;
	    this->dnPLoadSize = obj.dnPLoadSize;

	    this->totalFrameCount = obj.totalFrameCount;
	    this->frCount = obj.frCount;
	    this->upFrCount = obj.upFrCount;
	    this->dnFrCount = obj.dnFrCount;

	    this->frSize = obj.frSize;
	    this->upFrSize = obj.upFrSize;
	    this->dnFrSize = obj.dnFrSize;

	    this->sliceCounter = obj.sliceCounter;

	    this->pckArivalTimeEpochSec = obj.pckArivalTimeEpochSec;
	    this->pckLastTimeEpochSec = obj.pckLastTimeEpochSec;
	    this->pckLastTimeEpochNanoSec = obj.pckLastTimeEpochNanoSec;
	    this->startTimeEpochNanoSec = obj.startTimeEpochNanoSec;
	    this->endTimeEpochNanoSec = obj.endTimeEpochNanoSec;
	    this->startTimeEpochSec = obj.startTimeEpochSec;

	    strcpy(this->sIpv6, obj.sIpv6);
	    strcpy(this->dIpv6, obj.dIpv6);

	    this->sessionTP = obj.sessionTP;
	    this->peakSessionTP = obj.peakSessionTP;
	    this->upSessionTP = obj.upSessionTP;
	    this->dnSessionTP = obj.dnSessionTP;
	    this->upPeakSessionTP = obj.upPeakSessionTP;
	    this->dnPeakSessionTP = obj.dnPeakSessionTP;

	    this->causeCode = obj.causeCode;
	    this->protocolType = obj.protocolType;
	    this->ipV4sessionKey = obj.ipV4sessionKey;
	    this->ipV6sessionKey = obj.ipV6sessionKey;

	    packTimeMap = obj.packTimeMap;

	    this->mapIndex = obj.mapIndex;
	    this->poolIndex = obj.poolIndex;

		this->flushOrgId = obj.flushOrgId;
		this->flushTime = obj.flushTime;
		this->lastActivityTimeEpohSec = obj.lastActivityTimeEpohSec;
		this->activeState = obj.activeState;
		this->smInstanceId = obj.smInstanceId;
	}

	void copy(const _udpSession* obj)
	{
		state = obj->state;
		ipVer = obj->ipVer;
	    sPort = obj->sPort;
	    dPort = obj->dPort;

	    sIpv4 = obj->sIpv4;
	    dIpv4 = obj->dIpv4;

	    isUpDir = obj->isUpDir;
	    pckTotalTimeSec = obj->pckTotalTimeSec;

	    pLoadPkt = obj->pLoadPkt;
	    upPLoadPkt = obj->upPLoadPkt;
	    dnPLoadPkt = obj->dnPLoadPkt;

	    pLoadSize = obj->pLoadSize;
	    upPLoadSize = obj->upPLoadSize;
	    dnPLoadSize = obj->dnPLoadSize;

	    totalFrameCount = obj->totalFrameCount;

	    frCount = obj->frCount;
	    upFrCount = obj->upFrCount;
	    dnFrCount = obj->dnFrCount;

	    frSize = obj->frSize;
	    upFrSize = obj->upFrSize;
	    dnFrSize = obj->dnFrSize;

	    sliceCounter = obj->sliceCounter;

	    pckArivalTimeEpochSec = obj->pckArivalTimeEpochSec;
	    pckLastTimeEpochSec = obj->pckLastTimeEpochSec;
	    pckLastTimeEpochNanoSec = obj->pckLastTimeEpochNanoSec;
	    startTimeEpochNanoSec = obj->startTimeEpochNanoSec;
	    endTimeEpochNanoSec = obj->endTimeEpochNanoSec;
	    startTimeEpochSec = obj->startTimeEpochSec;

	    strcpy(sIpv6, obj->sIpv6);
	    strcpy(dIpv6, obj->dIpv6);

	    sessionTP = obj->sessionTP;
	    peakSessionTP = obj->peakSessionTP;
	    upSessionTP = obj->upSessionTP;
	    dnSessionTP = obj->dnSessionTP;
	    upPeakSessionTP = obj->upPeakSessionTP;
	    dnPeakSessionTP = obj->dnPeakSessionTP;

	    causeCode = obj->causeCode;
	    protocolType = obj->protocolType;
	    ipV4sessionKey = obj->ipV4sessionKey;
	    ipV6sessionKey = obj->ipV6sessionKey;

	    packTimeMap = obj->packTimeMap;
	    mapIndex = obj->mapIndex;
	    poolIndex = obj->poolIndex;

		flushOrgId = obj->flushOrgId;
		flushTime = obj->flushTime;
		lastActivityTimeEpohSec = obj->lastActivityTimeEpohSec;
		activeState = obj->activeState;
		smInstanceId = obj->smInstanceId;
	}
}udpSession;

typedef struct _aaaSession
{
	uint8_t 	ipVer;
	uint16_t 	sPort;
	uint16_t 	dPort;
	uint16_t 	reqCode;
	uint16_t 	respCode;
	uint16_t	packetIdentifier;
	uint16_t	mapIndex;
	uint16_t	flushType;
	uint32_t	accStatusType;
	uint32_t	serviceType;
	uint32_t	protocol;
	uint32_t 	sIp;
	uint32_t	accTerminationCause;
	uint32_t 	dIp;
	uint32_t	accAuth;
	uint32_t	framedIPLong;
	uint32_t	inputOctets;
	uint32_t	outputOctets;
	uint32_t	inputPackets;
	uint32_t	outputPackets;
	uint32_t	inputGigaWords;
	uint32_t	outputGigaWords;
	uint64_t 	StartTimeEpochMiliSec;
	uint64_t 	EndTimeEpochMiliSec;
	uint64_t	StartTimeEpochSec;
	uint64_t	EndTimeEpochSec;
	uint64_t	aaaKey;
	uint64_t 	flushTime;
	char		userName[AAA_USER_NAME_LEN];
	char		nasIP[16];
	char 		callingStationId[50];
	char		nasIdentifier[35];
	char		replyMsg[35];
	char		userIpV6[IPV6_ADDR_LEN];
	bool		ipv6AddressPrefixFlag;

	~_aaaSession(){}

	_aaaSession()
	{ reset(); }

	void reset()
	{
		StartTimeEpochMiliSec = 0;
		EndTimeEpochMiliSec = 0;
		StartTimeEpochSec	= 0;
		EndTimeEpochSec		= 0;
		sIp = 0;
		dIp = 0;
		sPort = 0;
		dPort = 0;
		ipVer = 0;
		reqCode = 0;
		respCode = 0;
		packetIdentifier = 0;

		protocol = 0;
		serviceType = 0;
		accStatusType = 0;
		accTerminationCause = 0;
		aaaKey = 0;
		accAuth = 0;
		mapIndex = 0;
		flushTime = 0;
		flushType = 0;

		userName[0] = 0;
		framedIPLong = 0;
		strcpy(nasIP, "NA");

		strcpy(callingStationId, "NA");
		strcpy(nasIdentifier, "NA");
		replyMsg[0] = 0;
		strcpy(userIpV6, "NA");
		ipv6AddressPrefixFlag = false;
		inputOctets	= 0;
		outputOctets	= 0;
		inputPackets	= 0;
		outputPackets	= 0;
		inputGigaWords = 0;
		outputGigaWords = 0;
	}

	_aaaSession(const _aaaSession& obj)
	{
		this->StartTimeEpochMiliSec 	= obj.StartTimeEpochMiliSec;
		this->EndTimeEpochMiliSec 		= obj.EndTimeEpochMiliSec;
		this->StartTimeEpochSec			= obj.StartTimeEpochSec;
		this->EndTimeEpochSec			= obj.EndTimeEpochSec;
		this->sIp 				= obj.sIp;
		this->dIp 					= obj.dIp;
		this->sPort 				= obj.sPort;
		this->dPort 					= obj.dPort;
		this->ipVer						= obj.ipVer;
		this->reqCode					= obj.reqCode;
		this->respCode					= obj.respCode;

		this->packetIdentifier 			= obj.packetIdentifier;

		this->protocol 					= obj.protocol;
		this->serviceType 				= obj.serviceType;
		this->accStatusType 			= obj.accStatusType;
		this->accTerminationCause 		= obj.accTerminationCause;
		this->aaaKey 			= obj.aaaKey;
		this->accAuth 					= obj.accAuth;
		this->mapIndex 					= obj.mapIndex;
		this->flushTime					= obj.flushTime;
		this->flushType					= obj.flushType;
		strcpy(this->userName, obj.userName);
		this->framedIPLong				= obj.framedIPLong;

		strcpy(this->nasIP, obj.nasIP);
		strcpy(this->callingStationId, obj.callingStationId);
		strcpy(this->nasIdentifier, obj.nasIdentifier);
		strcpy(this->replyMsg, obj.replyMsg);
		strcpy(this->userIpV6, obj.userIpV6);
		this->ipv6AddressPrefixFlag = obj.ipv6AddressPrefixFlag;
		this->inputOctets 	= obj.inputOctets;
		this->outputOctets	= obj.outputOctets;
		this->inputPackets  = obj.inputPackets;
		this->outputPackets = obj.outputPackets;
		this->inputGigaWords 	= obj.inputGigaWords;
		this->outputGigaWords	= obj.outputGigaWords;
	}

	void copy(const _aaaSession* obj)
	{
		this->StartTimeEpochMiliSec 	= obj->StartTimeEpochMiliSec;
		this->EndTimeEpochMiliSec 		= obj->EndTimeEpochMiliSec;
		this->StartTimeEpochSec			= obj->StartTimeEpochSec;
		this->EndTimeEpochSec			= obj->EndTimeEpochSec;

		this->sIp 				= obj->sIp;
		this->dIp 					= obj->dIp;
		this->sPort 				= obj->sPort;
		this->dPort 					= obj->dPort;
		this->ipVer						= obj->ipVer;
		this->reqCode					= obj->reqCode;
		this->respCode					= obj->respCode;

		this->packetIdentifier 			= obj->packetIdentifier;

		this->protocol 					= obj->protocol;
		this->serviceType 				= obj->serviceType;
		this->accStatusType 			= obj->accStatusType;
		this->accTerminationCause 		= obj->accTerminationCause;
		this->aaaKey 			= obj->aaaKey;
		this->accAuth 					= obj->accAuth;
		this->mapIndex 					= obj->mapIndex;
		this->flushTime					= obj->flushTime;
		this->flushType					= obj->flushType;
		strcpy(this->userName, obj->userName);
		this->framedIPLong				= obj->framedIPLong;
		strcpy(this->nasIP, obj->nasIP);
		strcpy(this->callingStationId, obj->callingStationId);
		strcpy(this->nasIdentifier, obj->nasIdentifier);
		strcpy(this->replyMsg, obj->replyMsg);
		strcpy(this->userIpV6, obj->userIpV6);
		this->ipv6AddressPrefixFlag = obj->ipv6AddressPrefixFlag;
		this->inputOctets 	= obj->inputOctets;
		this->outputOctets	= obj->outputOctets;
		this->inputPackets  = obj->inputPackets;
		this->outputPackets = obj->outputPackets;
		this->inputGigaWords 	= obj->inputGigaWords;
		this->outputGigaWords	= obj->outputGigaWords;
	}

}aaaSession;

//typedef struct _aaaSession
//{
//	uint8_t 	ipVer;
//	int16_t		nasPortType;
//	uint16_t	appPort;
//	uint16_t 	sourcePort;
//	uint16_t 	destPort;
//	uint16_t 	reqCode;
//	uint16_t 	respCode;
//	uint16_t	packetIdentifier;
//	uint16_t	mapIndex;
//	uint16_t	flushType;
//	uint32_t	accStatusType;
//	uint32_t	serviceType;
//	uint32_t	protocol;
//	uint32_t 	sourceAddr;
//	uint32_t	accTerminationCause;
//	uint32_t 	destAddr;
//	uint32_t	accAuth;
//	uint32_t	framedIPLong;
//	uint32_t	inputOctets;
//	uint32_t	outputOctets;
//	uint32_t	inputPackets;
//	uint32_t	outputPackets;
//	uint32_t	inputGigaWords;
//	uint32_t	outputGigaWords;
//	uint64_t 	StartTimeEpochMiliSec;
//	uint64_t 	EndTimeEpochMiliSec;
//	uint64_t	StartTimeEpochSec;
//	uint64_t	EndTimeEpochSec;
//	uint64_t	aaaKey;
//	uint64_t 	flushTime;
//	char 		sourceMacAddr[MAC_ADDR_LEN];
//	char 		destMacAddr[MAC_ADDR_LEN];
//	char		userName[RADIUS_USER_NAME_LEN];
//	char		nasIP[16];
//	char 		callingStationId[50];
//	char		nasIdentifier[35];
//	char		replyMsg[35];
//	char		userMac[MAC_ADDR_LEN];
//	char		userIpV6[IPV6_ADDR_LEN];
//	bool		ipv6AddressPrefixFlag;
//
//	~_aaaSession(){}
//
//	_aaaSession()
//	{ reset(); }
//
//	void reset()
//	{
//		StartTimeEpochMiliSec = 0;
//		EndTimeEpochMiliSec = 0;
//		StartTimeEpochSec	= 0;
//		EndTimeEpochSec		= 0;
//		sourceMacAddr[0] = 0;
//		destMacAddr[0] = 0;
//		appPort = 0;
//		sourceAddr = 0;
//		destAddr = 0;
//		sourcePort = 0;
//		destPort = 0;
//		ipVer = 0;
//		reqCode = 0;
//		respCode = 0;
//		packetIdentifier = 0;
//
//		protocol = 0;
//		nasPortType = -1;
//		serviceType = 0;
//		accStatusType = 0;
//		accTerminationCause = 0;
//		aaaKey = 0;
//		accAuth = 0;
//		mapIndex = 0;
//		flushTime = 0;
//		flushType = 0;
//
//		userName[0] = 0;
//		framedIPLong = 0;
//		strcpy(nasIP, "NA");
//
//		strcpy(callingStationId, "NA");
//		strcpy(nasIdentifier, "NA");
//		replyMsg[0] = 0;
//		userMac[0] = 0;
//		strcpy(userIpV6, "NA");
//		ipv6AddressPrefixFlag = false;
//		inputOctets	= 0;
//		outputOctets	= 0;
//		inputPackets	= 0;
//		outputPackets	= 0;
//		inputGigaWords = 0;
//		outputGigaWords = 0;
//	}
//
//	_aaaSession(const _aaaSession& obj)
//	{
//		this->StartTimeEpochMiliSec 	= obj.StartTimeEpochMiliSec;
//		this->EndTimeEpochMiliSec 		= obj.EndTimeEpochMiliSec;
//		this->StartTimeEpochSec			= obj.StartTimeEpochSec;
//		this->EndTimeEpochSec			= obj.EndTimeEpochSec;
//		strcpy(this->sourceMacAddr, obj.sourceMacAddr);
//		strcpy(this->destMacAddr, obj.destMacAddr);
//		this->appPort					= obj.appPort;
//		this->sourceAddr 				= obj.sourceAddr;
//		this->destAddr 					= obj.destAddr;
//		this->sourcePort 				= obj.sourcePort;
//		this->destPort 					= obj.destPort;
//		this->ipVer						= obj.ipVer;
//		this->reqCode					= obj.reqCode;
//		this->respCode					= obj.respCode;
//
//		this->packetIdentifier 			= obj.packetIdentifier;
//
//		this->protocol 					= obj.protocol;
//		this->nasPortType 				= obj.nasPortType;
//		this->serviceType 				= obj.serviceType;
//		this->accStatusType 			= obj.accStatusType;
//		this->accTerminationCause 		= obj.accTerminationCause;
//		this->aaaKey 			= obj.aaaKey;
//		this->accAuth 					= obj.accAuth;
//		this->mapIndex 					= obj.mapIndex;
//		this->flushTime					= obj.flushTime;
//		this->flushType					= obj.flushType;
//		strcpy(this->userName, obj.userName);
//		this->framedIPLong				= obj.framedIPLong;
//
//		strcpy(this->nasIP, obj.nasIP);
//		strcpy(this->callingStationId, obj.callingStationId);
//		strcpy(this->nasIdentifier, obj.nasIdentifier);
//		strcpy(this->replyMsg, obj.replyMsg);
//		strcpy(this->userMac, obj.userMac);
//		strcpy(this->userIpV6, obj.userIpV6);
//		this->ipv6AddressPrefixFlag = obj.ipv6AddressPrefixFlag;
//		this->inputOctets 	= obj.inputOctets;
//		this->outputOctets	= obj.outputOctets;
//		this->inputPackets  = obj.inputPackets;
//		this->outputPackets = obj.outputPackets;
//		this->inputGigaWords 	= obj.inputGigaWords;
//		this->outputGigaWords	= obj.outputGigaWords;
//	}
//
//	void copy(const _aaaSession* obj)
//	{
//		this->StartTimeEpochMiliSec 	= obj->StartTimeEpochMiliSec;
//		this->EndTimeEpochMiliSec 		= obj->EndTimeEpochMiliSec;
//		this->StartTimeEpochSec			= obj->StartTimeEpochSec;
//		this->EndTimeEpochSec			= obj->EndTimeEpochSec;
//
//		strcpy(this->sourceMacAddr, obj->sourceMacAddr);
//		strcpy(this->destMacAddr, obj->destMacAddr);
//		this->appPort					= obj->appPort;
//		this->sourceAddr 				= obj->sourceAddr;
//		this->destAddr 					= obj->destAddr;
//		this->sourcePort 				= obj->sourcePort;
//		this->destPort 					= obj->destPort;
//		this->ipVer						= obj->ipVer;
//		this->reqCode					= obj->reqCode;
//		this->respCode					= obj->respCode;
//
//		this->packetIdentifier 			= obj->packetIdentifier;
//
//		this->protocol 					= obj->protocol;
//		this->nasPortType 				= obj->nasPortType;
//		this->serviceType 				= obj->serviceType;
//		this->accStatusType 			= obj->accStatusType;
//		this->accTerminationCause 		= obj->accTerminationCause;
//		this->aaaKey 			= obj->aaaKey;
//		this->accAuth 					= obj->accAuth;
//		this->mapIndex 					= obj->mapIndex;
//		this->flushTime					= obj->flushTime;
//		this->flushType					= obj->flushType;
//		strcpy(this->userName, obj->userName);
//		this->framedIPLong				= obj->framedIPLong;
//		strcpy(this->nasIP, obj->nasIP);
//		strcpy(this->callingStationId, obj->callingStationId);
//		strcpy(this->nasIdentifier, obj->nasIdentifier);
//		strcpy(this->replyMsg, obj->replyMsg);
//		strcpy(this->userMac, obj->userMac);
//		strcpy(this->userIpV6, obj->userIpV6);
//		this->ipv6AddressPrefixFlag = obj->ipv6AddressPrefixFlag;
//		this->inputOctets 	= obj->inputOctets;
//		this->outputOctets	= obj->outputOctets;
//		this->inputPackets  = obj->inputPackets;
//		this->outputPackets = obj->outputPackets;
//		this->inputGigaWords 	= obj->inputGigaWords;
//		this->outputGigaWords	= obj->outputGigaWords;
//	}
//}aaaSession;

namespace DNSGlobal
{
	extern std::map<uint32_t, std::string> dnsLookUpMap[10];
	extern std::map<std::string, std::string> dnsV6LookUpMap;
}

namespace flusherStore
{
	extern std::unordered_map<uint32_t, tcpSession> tcp[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t tcpCnt[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, udpSession> udp[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t udpCnt[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, dnsSession> dns[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t dnsCnt[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, aaaSession> aaa[AAA_MAX_FLUSHER_SUPPORT][AAA_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t aaaCnt[AAA_MAX_FLUSHER_SUPPORT][AAA_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, tcpSession> utcp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t utcpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, udpSession> uudp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t uudpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	extern std::unordered_map<uint32_t, dnsSession> udns[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	extern uint32_t udnsCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
}

typedef enum{
	SYSTEM_CLEANUP_TCP_CONN_DATA		= 10,
	SYSTEM_CLEANUP_TCP_CONN_NODATA		= 11,
	SYSTEM_CLEANUP_TCP_NOCONN_DATA		= 12,
	SYSTEM_CLEANUP_TCP_NOCONN_NODATA	= 13,
	SYSTEM_CLEANUP_UDP_DATA				= 14,
	SYSTEM_CLEANUP_LONG_SESSION			= 16,
	SYSTEM_CLEANUP_TCP_DATA				= 17,
	SYSTEM_CLEANUP_END_OF_DAY_IP_DATA	= 18,

	SESSION_TERM_TCP_FIN_RECEIVED		= 20,
	SESSION_TERM_TCP_CONN_NODATA		= 21,
	SESSION_TERM_TCP_NOCONN_DATA		= 22,
	SESSION_TERM_TCP_NOCONN_NODATA		= 23,
	SESSION_TERM_TCP_OVERWRITE			= 24,
	SESSION_TERM_DNS_QUERY_SUCCESS		= 25,


	SYSTEM_PKTLIMIT_TCP_CONN_DATA		= 30,
	SYSTEM_PKTLIMIT_TCP_NOCONN_DATA		= 31,
	SYSTEM_PKTLIMIT_UDP_DATA			= 32,

	SYSTEM_TIMEOUT_TCP_CONN_DATA		= 33,
	SYSTEM_TIMEOUT_TCP_NOCONN_DATA		= 34,
	SYSTEM_TIMEOUT_UDP_DATA				= 35,

	DUPLICATE_SYN						= 40,
	FIN_NO_SESSION						= 50,

	SYSTEM_CLEANUP_DNS_QUERY			= 99,

}causeCode;

typedef enum{
	UD_SYN_TSVAL = 1,
	UD_SYSACK_TSVAL,
	UD_SYN_LATENCY,
	UD_TCP_DATA,
	UD_TCP_DISCONN,
	UD_UDP_DATA,
	CR_TCP_SESSION,
	CR_UDP_SESSION,
	UD_HTTP_DATA_REQ,
	UD_HTTP_DATA_RSP,
	UP_TCP_DATA_SLICE,
	TCP_UNKNOWN_PACKET_TYPE
}tcp_udp_commands;

typedef enum{
	SYN_RCV = 1,
	SYN_ACK_RCV,
	ACK_RCV,
	CONNECTED,
	DATA_RCV,
	FIN_RCV,
}IPState;

#endif /* PLUGINS_TCP_INC_SMGLOBAL_H_ */
