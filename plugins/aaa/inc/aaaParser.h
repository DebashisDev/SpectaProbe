/*
 * radiusTataSkyParser.h
 *
 *  Created on: Nov 10, 2017
 *      Author: Debashis
 */

#ifndef PLUGINS_RADIUS_SRC_RADIUSPARSER_H_
#define PLUGINS_RADIUS_SRC_RADIUSPARSER_H_

#include "../../aaa/inc/aaaGlobal.h"
#include "IPGlobal.h"
#include "SpectaTypedef.h"
#include "ProbeUtility.h"
#include "Log.h"
#include "BaseConfig.h"

class aaaParser : public BaseConfig, public ProbeUtility
{
	private:
		BYTE 	packet;
		void    hexDump(const void* pv, uint16_t len);
		bool	oltFlag;
		bool	process;

	public:
		aaaParser();
		~aaaParser();

		uint16_t parseAVPType(const BYTE packet, size_t offset, uint16_t remLen, MPacket *msgObj);

		string getAVPValue(uint16_t len, size_t bodyOffset, const BYTE packet);
		void parseAaaPacket(const BYTE packet, MPacket *msgObj);
};

#endif /* PLUGINS_RADIUS_SRC_RADIUSPARSER_H_ */
