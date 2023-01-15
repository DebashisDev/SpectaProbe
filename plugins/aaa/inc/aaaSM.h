/*
 * aaaSM.h
 *
 *  Created on: 22 Sep 2021
 *      Author: debas
 */

#ifndef PLUGINS_AAA_SRC_AAASM_H_
#define PLUGINS_AAA_SRC_AAASM_H_

#include <time.h>
#include <sys/time.h>
#include <sstream>
#include <locale.h>

#include "IPGlobal.h"
#include "smGlobal.h"
#include "Log.h"
#include "aaaSMInterface.h"

using namespace std;

class aaaSM : BaseConfig
{
	public:
		aaaSM(uint16_t id);
		~aaaSM();

		void		run();
		bool  		isAaaSMReady();

	private:
		void		lockAAAMap();
		void		unLockAAAMap();

		uint16_t	instanceId;
		uint16_t 	lastIndex, curIndex;
		uint16_t 	curIndexClnUp, lastIndexClnUp;


		bool 		aaaSMReadyState = false;
		long 		processStartEpochSec = 0;

		aaaSMInterface*	pAaaSMInterface;

		void 			aaaProcessQueue(uint16_t t_index);
		void 			processQueue(bool &smBusy, uint32_t &smCnt, std::unordered_map<uint32_t, MPacket> &pkt);
		void 			aaaProcessPacket(MPacket *pkt);
};

#endif /* PLUGINS_AAA_SRC_AAASM_H_ */
