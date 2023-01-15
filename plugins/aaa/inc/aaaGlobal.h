/*
 * radiusGlobal.h
 *
 *  Created on: Oct 20, 2016
 *      Author: Debashis
 */

#ifndef PLUGINS_RADIUS_SRC_RADIUSGLOBAL_H_
#define PLUGINS_RADIUS_SRC_RADIUSGLOBAL_H_

#include <map>
#include <unordered_map>
#include "IPGlobal.h"
#include "SpectaTypedef.h"

using namespace std;

/* Definition of RADIUS Code (RFC 2865) */

#define ACCESS_REQUEST			1
#define ACCESS_ACCEPT			2
#define ACCESS_REJECT			3

#define ACCOUNTING_REQUEST		4
#define ACCOUNTING_RESPONSE		5

#define	ACCOUNTING_START		1
#define	ACCOUNTING_STOP			2
#define ACCOUNTING_UPDATE		3

#define FLUSH_REQ_RSP			30
#define FLUSH_RSP_REQ			31
#define FLUSH_DUPLICATE			32
#define FLUSH_CLEANUP			33

#define AUTHENTICATOR_LEN		16

/* Definition of Attributes (RFC 2865 & 2866) */

#define USER_NAME				1
#define USER_PASSWORD			2
#define CHAP_PASSWORD			3
#define NAS_IP_ADDRESS			4
#define NAS_PORT				5
#define SERVICE_TYPE			6
#define FRAMED_PROTOCOL			7
#define FRAMED_IP_ADDRESS		8
#define FRAMED_IP_NETMASK		9
#define FRAMED_ROUTING			10
#define FILTER_ID				11
#define FRAMED_MTU				12
#define FRAMED_COMPRESSION		13
#define LOGIN_IP_HOST			14
#define LOGIN_SERVICE			15
#define LOGIN_TCP_PORT			16
//(UNASSIGNED)					17
#define REPLY_MESSAGE			18
#define CALLBACK_NUMBER			19
#define CALLBACK_ID				20
//(UNASSIGNED)					21
#define FRAMED_ROUTE			22
#define FRAMED_IPX_NETWORK		23
#define STATE					24
#define CLASS					25
#define VENDOR_SPECIFIC			26
#define SESSION_TIMEOUT			27
#define IDLE_TIMEOUT			28
#define TERMINATION_ACTION		29
#define CALLED_STATION_ID		30
#define CALLING_STATION_ID		31
#define NAS_IDENTIFIER			32
#define PROXY_STATE				33
#define LOGIN_LAT_SERVICE		34
#define LOGIN_LAT_NODE			35
#define LOGIN_LAT_GROUP			36
#define FRAMED_APPLETALK_LINK	37
#define FRAMED_APPLETALK_NETWORK 38
#define FRAMED_APPLETALK_ZONE	39
#define ACCT_STATUS_TYPE		40
#define ACCT_DELAY_TIME			41
#define ACCT_INPUT_OCTETS		42
#define ACCT_OUTPUT_OCTETS		43
#define ACCT_SESSION_ID			44
#define ACCT_AUTHENTIC			45
#define ACCT_SESSION_TIME		46
#define ACCT_INPUT_PACKETS		47
#define ACCT_OUTPUT_PACKETS		48
#define ACCT_TERMINATE_CAUSE	49
#define ACCT_MULTI_SESSION_ID	50
#define ACCT_LINK_COUNT			51
#define ACCT_INPUT_GIGAWORDS	52
#define ACCT_OUTPUT_GIGAWORDS	53
#define CHAP_CHALLENGE			60
#define NAS_PORT_TYPE			61
#define PORT_LIMIT				62
#define LOGIN_LAT_PORT			63
#define DELEGATED_IPV6_PREFIX	123

/* VSA (Vendor Specific Attributes) Type */
#define USER_AGENT_CIRCUIT_ID	1	/* OLT 	*/
#define SUBSC_ID				11
#define SUBSC_PROF				12	/* Subscriber Profile 	*/
#define SLA_PROF				13	/* Subscriber Plan 		*/
#define CLIENT_HW_ADDR			27	/* Subscriber MAC Address */

//#define CALCULATE_SUBNETMASK(subnetMask) ((subnetMask / 16) * 2)
#define CALCULATE_SUBNETMASK(subnetMask) ((subnetMask / 15) * 4)

#define	OCTATE 					1
#define INVALID					6

namespace radiusStats
{
	extern uint32_t aaaSessionCnt[5];
	extern uint32_t aaaSessionScanned[5];
	extern uint32_t aaaSessionCleaned[5];
	extern uint32_t accSessionCnt[5];
	extern uint32_t accoSessionCnt[5];

	extern uint32_t aaaGlbUserIdCnt;
	extern uint32_t aaaGlbUserIpCnt;

}

typedef struct _userInfo
{
	uint32_t	allocatedIpLong;						/* User Ip Long */
	uint32_t	oldAllocatedIpLong;						/* User Ip Long */
	char 		userName[AAA_USER_NAME_LEN];			/* User Name */
	char		allocatedIp[IPV6_ADDR_LEN];				/* Allocated IP */
	char		oldAllocatedIp[IPV6_ADDR_LEN];			/* Old Allocated IP */

	~_userInfo(){};

	_userInfo()
	{ reset(); }

	void reset()
	{
		allocatedIpLong = 0;
		oldAllocatedIpLong = 0;
		strcpy(userName, "NA");
		strcpy(allocatedIp, "NA");
		strcpy(oldAllocatedIp, "NA");
    }
}userInfo;

typedef struct _userInfoMac
{
	char 		userId[50];		/* User IP Address */
	string		userPlan;	/* User Plan */
	string		OLT;
	_userInfoMac()
	{
		strcpy(userId, "NA");
		userPlan.assign("NA");
		OLT.assign("NA");
    }
}userInfoMac;

namespace aaaGlbMap
{
	extern std::map<uint32_t, userInfo> aaaGlbUserIpMap;	/* 01295072520@airtelbroadband.in */
	extern std::map<string, userInfo> aaaGlbUserIdMap;
	extern std::map<std::string, userInfo> aaaGlbIpv6UserMap;
}

class aaaGlobal
{
	public:
		aaaGlobal();
		~aaaGlobal();
};


#endif /* PLUGINS_RADIUS_SRC_RADIUSGLOBAL_H_ */
