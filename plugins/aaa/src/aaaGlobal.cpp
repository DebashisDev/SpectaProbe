/*
 * radiusGlobal.cpp
 *
 *  Created on: Oct 20, 2016
 *      Author: Debashis
 */

#include "aaaGlobal.h"

aaaGlobal::aaaGlobal()
{ }

aaaGlobal::~aaaGlobal()
{ }

namespace radiusStats
{
	uint32_t aaaSessionCnt[5] 		= {0};
	uint32_t aaaSessionScanned[5] 	= {0};
	uint32_t aaaSessionCleaned[5] 	= {0};

	uint32_t accSessionCnt[5] 		= {0};
	uint32_t accoSessionCnt[5] 		= {0};

	uint32_t aaaGlbUserIdCnt		= 0;
	uint32_t aaaGlbUserIpCnt		= 0;
}

namespace aaaGlbMap
{
	std::map<uint32_t, userInfo> aaaGlbUserIpMap;	/* 01295072520@airtelbroadband.in */
	std::map<string, userInfo> aaaGlbUserIdMap;
	std::map<std::string, userInfo> aaaGlbIpv6UserMap;
}
