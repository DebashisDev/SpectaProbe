/*
 * TCPUDPGlobal.cpp
 *
 *  Created on: 15-Jul-2016
 *      Author: deb
 */

#include "smGlobal.h"

using namespace std;


namespace DNSGlobal
{
	std::map<uint32_t, std::string> dnsLookUpMap[10];
	std::map<std::string, std::string> dnsV6LookUpMap;
}

namespace flusherStore
{
	std::unordered_map<uint32_t, tcpSession> tcp[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t tcpCnt[TCP_MAX_FLUSHER_SUPPORT][TCP_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, udpSession> udp[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t udpCnt[UDP_MAX_FLUSHER_SUPPORT][UDP_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, dnsSession> dns[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t dnsCnt[DNS_MAX_FLUSHER_SUPPORT][DNS_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, aaaSession> aaa[AAA_MAX_FLUSHER_SUPPORT][AAA_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t aaaCnt[AAA_MAX_FLUSHER_SUPPORT][AAA_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, tcpSession> utcp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t utcpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, udpSession> uudp[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t uudpCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];

	std::unordered_map<uint32_t, dnsSession> udns[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
	uint32_t udnsCnt[UNM_MAX_FLUSHER_SUPPORT][UNM_MAX_SESSION_MANAGER_SUPPORT][10];
}

//namespace unMappedFlusherStore
//{
//	std::unordered_map<uint32_t, tcpSession> uIp[10];
//	uint32_t uIpCnt[10] = {0};
//
//	std::unordered_map<uint32_t, xdrStore> uIpXdr[10];
//	uint32_t uIpXdrCnt[10] = {0};
//
//	std::unordered_map<uint32_t, dnsSession> uDns[10];
//	uint32_t uDnsCnt[10] = {0};
//
//	std::unordered_map<uint32_t, xdrStore> uDnsXdr[10];
//	uint32_t uDnsXdrCnt[10]= {0};
//}
