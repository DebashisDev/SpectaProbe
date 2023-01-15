/*
 * RadiusFlusher.h
 *
 *  Created on: 17-Sep-2019
 *      Author: singh
 */

#ifndef PLUGINS_AAA_INC_AAAFLUSHER_H_
#define PLUGINS_AAA_INC_AAAFLUSHER_H_

#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "aaaFlushUtility.h"
#include "aaaGlobal.h"
#include "IPGlobal.h"
#include "smGlobal.h"
#include "Log.h"
#include "ProbeUtility.h"
#include "BaseConfig.h"

class aaaFlusher : BaseConfig
{
	private:
		uint16_t		instanceId;
		bool			initStatus;
		char 			csvXdr[XDR_MAX_LEN];
		fstream			aaaXdrHandler;

		aaaFlushUtility 	*rfUtility;

		void 	processData(uint16_t index);
		void 	getAaaData(uint32_t &radiusFlushMap_sm_cnt, std::unordered_map<uint32_t, aaaSession> &flushMap);
		bool 	createAaaXdrData(aaaSession *pAaaSession);

		void 	openAaaXdrFile(uint16_t currentMin, uint16_t currentHour, uint16_t currentDay, uint16_t currentMonth, uint16_t currentYear);
		void 	closeAaaXdrFile();

	public:
		aaaFlusher(uint16_t id);
		~aaaFlusher();
		bool 	isInitialized();
		void 	run();
};

#endif /* PLUGINS_AAA_INC_AAAFLUSHER_H_ */
