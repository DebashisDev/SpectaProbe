/*
 * radiusFlushUtility.h
 *
 *  Created on: May 4, 2017
 *      Author: Debashis
 */

#ifndef PLUGINS_RADIUS_SRC_RADIUSFLUSHUTILITY_H_
#define PLUGINS_RADIUS_SRC_RADIUSFLUSHUTILITY_H_

#include "smGlobal.h"
#include "aaaGlobal.h"
#include "Log.h"

class aaaFlushUtility
{
	public:
		aaaFlushUtility();
		~aaaFlushUtility();
		void buildAaaXdr(aaaSession *pRadiusSession, char *xdr);
};

#endif /* PLUGINS_RADIUS_SRC_RADIUSFLUSHUTILITY_H_ */
