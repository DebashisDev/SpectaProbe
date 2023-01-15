/*
 * radiusSessionManager.h
 *
 *  Created on: Oct 22, 2016
 *      Author: Debashis
 */

#ifndef PLUGINS_RADIUS_SRC_RADIUSSESSIONMANAGER_H_
#define PLUGINS_RADIUS_SRC_RADIUSSESSIONMANAGER_H_

#include "aaaGlobal.h"
#include "IPGlobal.h"
#include "smGlobal.h"
#include "Log.h"
#include "BaseConfig.h"

#define START_STATUS_TYPE  	1
#define STOP_STATUS_TYPE  	2
#define UPDATE_STATUS_TYPE  3

class aaaSMInterface  : BaseConfig
{
	private:
		uint16_t 	instanceId;
		uint32_t 	cleanUpCnt;

		std::map<uint64_t, aaaSession> radiusAccessMap[AAA_SESSION_POOL_ARRAY_SIZE];
		std::map<uint64_t, aaaSession> radiusAccountingMap[AAA_SESSION_POOL_ARRAY_SIZE];

		std::map<uint64_t, uint32_t> radiusCleanMap;

		void			getSessionKey(MPacket *msgObj);
		void 			timedOutCleanSession(uint64_t key, aaaSession *pRadiusSession, uint32_t count);

		aaaSession*		getAccessSession(MPacket *msgObj, bool *found);
		aaaSession*		getAccountingSession(MPacket *msgObj, bool *found);

		void 			eraseSession(aaaSession *pRadiusSession);
		void 			createSession(aaaSession *pRadiusSession, MPacket *msgObj);
		void 			updateSession(aaaSession *pRadiusSession, MPacket *msgObj);

		void 			processAccessRequest(MPacket *msgObj);
		void 			processAccessResponse(MPacket *msgObj);

		void 			processAccountingRequest(MPacket *msgOb);
		void 			processAccountingResponse(MPacket *msgOb);

		void 			flushRadiusSession(aaaSession *pRadiusSession, bool erase, uint16_t flushType);
		void 			storeRadiusSession(uint16_t idx, aaaSession *pRadiusSession);

		void			eraseAccessSession();
		void			eraseAccountingSession();

		void			updateGlbIPTable(aaaSession *pRadiusSession);

	public:
		aaaSMInterface(uint16_t id);
		~aaaSMInterface();

		void 	aaaLockMap();
		void 	aaaUnLockMap();

		void 	packetEntry(MPacket *msgObj);
		void 	aaaTimeOutCleanSession();
};

#endif /* PLUGINS_RADIUS_SRC_RADIUSSESSIONMANAGER_H_ */
