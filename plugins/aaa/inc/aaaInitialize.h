/*
 * radiusInitialize.h
 *
 *  Created on: Aug 31, 2017
 *      Author: Debashis
 */

#ifndef PLUGINS_RADIUS_SRC_RADIUSINITIALIZE_H_
#define PLUGINS_RADIUS_SRC_RADIUSINITIALIZE_H_

#include "SpectaTypedef.h"

class aaaInitialize
{
	public:
		aaaInitialize();
		~aaaInitialize();

		static void aaaInitCode();
		static void aaaInitServiceType();
		static void aaaInitProtocol();
		static void aaaInitAccAuth();
		static void	aaaInitAccTerminate();
		static void	aaaInitAccStatus();
		static void	aaaInitNasPortType();
};

#endif /* PLUGINS_RADIUS_SRC_RADIUSINITIALIZE_H_ */
