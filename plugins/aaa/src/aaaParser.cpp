/*
 * radiusLink3Parser.cpp
 *
 *  Created on: Nov 10, 2017
 *      Author: Debashis
 */

#include "aaaParser.h"

#include <algorithm>

using namespace std;

aaaParser::aaaParser()
{
	this->_name = "RadiusParser";
	this->setLogLevel(Log::theLog().level());

	this->packet = NULL;
	this->oltFlag = false;
	this->process = false;
}

aaaParser::~aaaParser()
{ }

void aaaParser::hexDump(const void* pv, uint16_t len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
}

void aaaParser::parseAaaPacket(const BYTE packet, MPacket *msgObj)
{
	size_t offset = 0;
	uint16_t avp_len = 0;
	uint16_t radiusRemainingLen = 0;

	process = false;

	this->packet = packet + UDP_HDR_LEN; // 8 bytes -- UDP Header Size

	msgObj->aaaCode = VAL_BYTE(this->packet + offset);
	offset += 1;	// Code 1 Byte

	if(msgObj->aaaCode < ACCESS_REQUEST && msgObj->aaaCode > ACCOUNTING_RESPONSE)
	{
		msgObj->pType = 0;
		return;
	}

	msgObj->aaaIdentifier = VAL_BYTE(this->packet + offset);

	offset += 1;	// Packet Identifier 1 Byte

	int rediusLen = VAL_USHORT(this->packet + offset);

	offset += 2;	// Radius Length 2 Byte

	/* implemented in case of YouBB */
	int authenticator = VAL_BYTE(this->packet + offset);

	if(authenticator == 0)
	{
		msgObj->pType = 0;
		return;
	}
	offset += AUTHENTICATOR_LEN;

	if(rediusLen < msgObj->frByteLen)
		radiusRemainingLen = rediusLen - offset; //bodyOffset;
	else
		radiusRemainingLen = msgObj->frByteLen - offset;

	while(radiusRemainingLen > 0 && avp_len >= 0)
	{
		avp_len = parseAVPType(this->packet, offset, radiusRemainingLen, msgObj); //Attribute-Value Pairs (AVP)

		/* Some Error Indecording or Wrong Radius Packet */
		if(avp_len == 0)
		{
			if(process == false && msgObj->aaaCode == 4) msgObj->pType = 0;
			return;
		}

		radiusRemainingLen -= avp_len;
		offset += avp_len;
	}
}

uint16_t aaaParser::parseAVPType(const BYTE packet, size_t bodyOffset, uint16_t remLen, MPacket *msgObj)
{
	std::string value;

	char addr[16];
	addr[0] = 0;

	uint16_t type = VAL_BYTE(this->packet + bodyOffset);
	bodyOffset += 1;		/* Type Length */
	uint16_t length = VAL_BYTE(this->packet + bodyOffset);

	if(remLen < length) return -1;

	bodyOffset += 1;	/* Length */

	switch(type)
	{
		case USER_NAME:
					if(length > 3 && length <= 32)
					{
                        uint16_t check = VAL_BYTE(this->packet + bodyOffset);
						if(check >= 32)		// Avoid non-printable charactors
						{
							std::string name = getAVPValue(length - 2, bodyOffset, packet);
							std::replace(name.begin(), name.end(), ',', '.');

							strcpy(msgObj->userName, name.c_str());
						}
					}
					else
					{ return 0; }

					break;

		case SERVICE_TYPE:
					if(length != 6)
						return 0;

					msgObj->aaaServiceType = VAL_ULONG(packet + bodyOffset);
					break;

		case FRAMED_PROTOCOL:
					if(length != 6)
						return 0;

					msgObj->aaaProtocol = VAL_ULONG(packet + bodyOffset);
					break;

		case FRAMED_IP_ADDRESS:
					if(length != 6)
						return 0;

					msgObj->aaaFramedIp =(msgObj->aaaFramedIp << 8) + (0xff & packet[bodyOffset]);
					msgObj->aaaFramedIp=(msgObj->aaaFramedIp << 8) + (0xff & packet[bodyOffset + 1]);
					msgObj->aaaFramedIp=(msgObj->aaaFramedIp << 8) + (0xff & packet[bodyOffset + 2]);
					msgObj->aaaFramedIp=(msgObj->aaaFramedIp << 8) + (0xff & packet[bodyOffset + 3]);

					process = true;
					break;

		case REPLY_MESSAGE:
					value.clear();

					if(length > 3 && length <= 50) {
						for(uint16_t count = 0; count < (length - 2); count++) {
							if(isprint(packet[bodyOffset + count]) != 0)
								value.append(1, packet[bodyOffset + count]);
						}
						strcpy(msgObj->replyMsg, value.c_str());
					}
					else
					{ return 0; }

					break;

		case ACCT_TERMINATE_CAUSE:
					if(length != 6)
						return 0;

					msgObj->aaaTerminationCause = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_STATUS_TYPE:
					if(length != 6)
						return 0;

					msgObj->accStatusType = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_AUTHENTIC:
					if(length != 6)
						return 0;

					msgObj->accAuth = VAL_ULONG(packet + bodyOffset);
					break;


		case ACCT_INPUT_OCTETS:
						if(length != 6)
							return 0;

						msgObj->inputOctets = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_OUTPUT_OCTETS:
						if(length != 6)
							return 0;

						msgObj->outputOctets = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_INPUT_PACKETS:
						if(length != 6)
							return 0;

						msgObj->inputPackets = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_OUTPUT_PACKETS:
						if(length != 6)
							return 0;

						msgObj->outputPackets = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_INPUT_GIGAWORDS:
						if(length != 6)
							return 0;

						msgObj->inputGigaWords = VAL_ULONG(packet + bodyOffset);
					break;

		case ACCT_OUTPUT_GIGAWORDS:
						if(length != 6)
							return 0;

						msgObj->outputGigaWords = VAL_ULONG(packet + bodyOffset);
					break;
		default:
				break;
	}
	return length;
}


string aaaParser::getAVPValue(uint16_t len, size_t bodyOffset, const BYTE packet)
{
	std::string val;
	val.clear();

	// 8 = 4 Bytes (Code) + 1 Byte (Flag) + 3 Bytes AVP Length
	for(int count = 0; count < len; count++) {
		val.append(1, packet[bodyOffset + count]);
	}
	return val;
}
