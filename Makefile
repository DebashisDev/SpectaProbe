#########################################################################
#																		#
# SCRIPT NAME	: Makefile												#
# DESCRIPTION	: To build the SpectaProbe along with user librarys		#
# DATE 			: 19-02-2016										    #
# AUTHOR		: Debashis.											    #
#																		#
# To make FL probe : make flclean; make flprobe 						#
# Copyright (c) 2016, Pinnacle Digital (P) Ltd. New-Delhi.				# 
#########################################################################

# Include all the header directories.
include ${PROBE_ROOT}/probe.mk

PROBE_DIRS = 		\
	${CORE_SRC} 	\
	${ETH_SRC} 		\
	${SF_SRC} 		\
	${TCP_SRC} 		\
	${UDP_SRC} 		\
	${DNS_SRC} 		\
	${AAA_SRC} 		\
	${UNM_SRC}		\
	${LOG_SRC} 
	

#########################################################################
# SCP Platform and Platform Library File Name							#
#########################################################################
PROBE_TARGET = ${PROBE_BIN}/spectaProbeFL

#System Library
PCAPLIB 	= pcap
THRLIB 		= pthread
ZMQLIB 		= zmq
SOLARLIB	= ${PROBE_ROOT}/lib/libciul.so

LIBS 		= -lm -ldl -l$(PCAPLIB) -l$(THRLIB) -l$(ZMQLIB)

#########################################################################
# For SpectaProbe
#########################################################################
probe:
	echo ${PROBE_DIRS}
	for i in ${PROBE_DIRS}; \
	do \
		(cd $$i; \
		echo "*******" $$i; \
		${MAKE} all \
		); \
	done

	${GCC} -o ${PROBE_TARGET} ${SOLARLIB}	\
				${CORE_SRC}/*.o 	\
				${ETH_SRC}/*.o 		\
				${SF_SRC}/*.o 		\
				${TCP_SRC}/*.o 		\
				${UDP_SRC}/*.o 		\
				${DNS_SRC}/*.o 		\
				${AAA_SRC}/*.o 		\
				${UNM_SRC}/*.o		\
				${LOG_SRC}/*.o 		\
				${LIBS}

#########################################################################

clean:
	for i in ${PROBE_DIRS}; \
	do \
		(cd $$i; \
		echo $$i; \
		${MAKE} clean \
		); \
	done

	${RM} ${PROBE_TARGET}
	