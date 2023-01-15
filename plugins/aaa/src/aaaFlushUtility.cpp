/*
 * radiusFlushUtility.cpp
 *
 *  Created on: May 4, 2017
 *      Author: Debashis
 */

#include "aaaFlushUtility.h"

aaaFlushUtility::aaaFlushUtility()
{ }

aaaFlushUtility::~aaaFlushUtility()
{ }

void aaaFlushUtility::buildAaaXdr(aaaSession *pRadiusSession, char *xdr)
{
	char ProtocalType[15];
	char sourceIp[IPV6_ADDR_LEN], destIp[IPV6_ADDR_LEN];
	char ipvAddress[IPV6_ADDR_LEN];

	xdr[0] = ProtocalType[0] = ipvAddress[0] = 0;

	if(pRadiusSession->ipVer == IPVersion4)
	{
		sourceIp[0] = destIp[0] = 0;
		long2Ip(pRadiusSession->sIp, sourceIp);
		long2Ip(pRadiusSession->dIp, destIp);
	}
	else
	{ return; }

	if(pRadiusSession->StartTimeEpochMiliSec > pRadiusSession->EndTimeEpochMiliSec)
	{
		uint64_t temp = pRadiusSession->StartTimeEpochMiliSec;
		pRadiusSession->StartTimeEpochMiliSec = pRadiusSession->EndTimeEpochMiliSec;
		pRadiusSession->EndTimeEpochMiliSec = temp;
	}
	long2Ip(pRadiusSession->framedIPLong, ipvAddress);

	if(pRadiusSession->ipv6AddressPrefixFlag)
		strcpy(ipvAddress, pRadiusSession->userIpV6);

	sprintf(xdr, "%d,%d,%d,%s,"		// 01- Probe Id,       02- XDR Id, 		       03- App Port,      04- Protocol Desc,
				 "%u,%s,"			// 05- Protocol,       06- framed Protocol,
				 "%lu,"				// 07- Session Key
				 "%s,%s,"			// 08- Source Mac,     09- Dest Mac,
			 	 "%s,%d,%s,%d,"		// 10- Source Ip,      11- Source Port,        12- Dest Ip,       13- Dest Port
				 "%lu,%lu,"			// 14- Start Time,     15- End Time,
				 "%d,%s,"			// 16- Req Code,       17- Req Code Desc,
				 "%s,%s,%s,%s,"		// 18- User Name,	   19- framed IP,      	   20- NAS IP,		  21- Calling Station Id
				 "%u,%s,%s,"		// 22- Service Type	   23- Service Type Desc   24- NAS Identifier
				 "%s,%s,"			// 25- User Plan, 	   26- User Policy Plan,
				 "%u,%s,"			// 27- Acc Status Type,28- Acc Status Type Desc,
				 "%u,%s,"			// 29- Termination C,  30- Termination C Desc,
				 "%d,%s,"			// 31- Resp Code,      32- Resp Code Desc,
				 "%d,%s,%d,"		// 33- NAS Port Type,  34- NAS Port Type Desc, 35- SessionTimeOut
				 "%u,%s,%s,"		// 36- Acc Auth,       37- Acc Auth Desc,	   38- Reply Msg
				 "%lu,%d,%s,%s,%s,"	// 39- Flush Time      40- Flush Type		   41- OLT    		  42- IPv6      43- User Mac
				 "%u,%u,%d,%d,%d,"	// 44- Input Octets	   45- Output Octets	   46- Session Time   47- InputPackets    48- Output Packets
				 "%u,%u",			// 49- Input Gigawords 50- Output Gigawords

				Global::PROBE_ID, AAA_XDR_ID, pRadiusSession->dPort, initalize::protocolName[pRadiusSession->dPort].c_str(),
				pRadiusSession->protocol, initalize::framedProtocolMap[pRadiusSession->protocol].c_str(),
				pRadiusSession->aaaKey,
				"NA", "NA",
				sourceIp, pRadiusSession->sPort, destIp, pRadiusSession->dPort,
				pRadiusSession->StartTimeEpochMiliSec, pRadiusSession->EndTimeEpochMiliSec,
				pRadiusSession->reqCode, initalize::radiusCodeMap[pRadiusSession->reqCode].c_str(),
				pRadiusSession->userName, ipvAddress, /*pRadiusSession->nasIP*/ "NA", pRadiusSession->callingStationId,
				pRadiusSession->serviceType, initalize::serviceTypeMap[pRadiusSession->serviceType].c_str(), pRadiusSession->nasIdentifier,
				"NA", "NA",
				pRadiusSession->accStatusType, initalize::acctStatusMap[pRadiusSession->accStatusType].c_str(),
				pRadiusSession->accTerminationCause, initalize::acctTeminateMap[pRadiusSession->accTerminationCause].c_str(),
				pRadiusSession->respCode, initalize::radiusCodeMap[pRadiusSession->respCode].c_str(),
				0, "NA", 0,
				pRadiusSession->accAuth, initalize::acctAuthenticMap[pRadiusSession->accAuth].c_str(), pRadiusSession->replyMsg,
				pRadiusSession->flushTime, pRadiusSession->flushType, "NA", pRadiusSession->userIpV6, "NA",
				pRadiusSession->inputOctets, pRadiusSession->outputOctets, 0, 0, 0,
				pRadiusSession->inputGigaWords, pRadiusSession->outputGigaWords);
		return;
}
