/*
 * radiusInitialize.cpp
 *
 *  Created on: Aug 31, 2017
 *      Author: Debashis
 */

#include "aaaInitialize.h"
#include "aaaGlobal.h"

aaaInitialize::aaaInitialize()
{ }

aaaInitialize::~aaaInitialize()
{ }

void aaaInitialize::aaaInitCode()
{
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(1, "Access-Request"));
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(2, "Access-Accept"));
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(3, "Access-Reject"));
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(4, "Accounting-Request"));
	initalize::radiusCodeMap.insert(std::pair<uint16_t, std::string>(5, "Accounting-Response"));
}

void aaaInitialize::aaaInitServiceType()
{
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(1, "Login"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(2, "Framed"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(3, "Callback Login"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(4, "Callback Framed"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(5, "Outbound"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(6, "Administrative"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(7, "NAS Prompt"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(8, "Authenticate Only"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(9, "Callback NAS Prompt"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(10, "Call Check"));
	initalize::serviceTypeMap.insert(std::pair<uint16_t, std::string>(11, "Callback Administrative"));
}

void aaaInitialize::aaaInitProtocol()
{
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(1, "PPP"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(2, "SLIP"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(3, "ARAP"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(4, "SingleLink/MultiLink Protocol"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(5, "IPX/SLIP"));
	initalize::framedProtocolMap.insert(std::pair<uint16_t, std::string>(6, "X.75 Synchronous"));
}

void aaaInitialize::aaaInitAccAuth()
{
	initalize::acctAuthenticMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::acctAuthenticMap.insert(std::pair<uint16_t, std::string>(1, "Radius"));
	initalize::acctAuthenticMap.insert(std::pair<uint16_t, std::string>(2, "Local"));
	initalize::acctAuthenticMap.insert(std::pair<uint16_t, std::string>(3, "Remote"));
}

void aaaInitialize::aaaInitAccTerminate()
{
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(1, "User Request"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(2, "Lost Carrier"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(3, "Lost Service"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(4, "Idle Timeout"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(5, "Session Timeout"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(6, "Admin Reset"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(7, "Admin Reboot"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(8, "Port Error"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(9, "NAS Error"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(10, "NAS Request"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(11, "NAS Reboot"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(12, "Port Unneeded"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(13, "Port Preempted"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(14, "Port Suspended"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(15, "Service Unavailable"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(16, "Callback"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(17, "User Error"));
	initalize::acctTeminateMap.insert(std::pair<uint16_t, std::string>(18, "Host Request"));
}

void aaaInitialize::aaaInitAccStatus()
{
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(0, "NA"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(1, "Start"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(2, "Stop"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(3, "Interim-Update"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(7, "Accounting-On"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(8, "Accounting-Off"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(9, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(10, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(11, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(12, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(13, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(14, "Reserved for Tunnel Accounting"));
	initalize::acctStatusMap.insert(std::pair<uint16_t, std::string>(15, "Reserved for Failed"));
}

void aaaInitialize::aaaInitNasPortType()
{
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(-1, "NA"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(0, "Async"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(1, "Sync"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(2, "ISDN Sync"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(3, "ISDN Async V.120"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(4, "ISDN Async V.110"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(5, "Virtual"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(6, "PIAFS"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(7, "HDLC Clear Channel"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(8, "X.25"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(9, "X.75"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(10, "G.3 Fax"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(11, "SDSL - Symmetric DSL"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(12, "ADSL-CAP"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(13, "ADSL-DMT"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(14, "IDSL"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(15, "Ethernet"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(16, "xDSL"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(17, "Cable"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(18, "Wireless - Others"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(19, "Wireless - IEEE 802.11"));
	initalize::nasPortTypeMap.insert(std::pair<uint16_t, std::string>(33, "PPPoEoVLAN"));
}
