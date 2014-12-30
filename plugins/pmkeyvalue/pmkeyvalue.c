/* pmkeyvalue.c
 * This is a parser module for RFC3164(legacy syslog)-formatted messages.
 *
 * NOTE: read comments in module-template.h to understand how this file
 *       works!
 *
 * File begun on 2009-11-04 by RGerhards
 *
 * Copyright 2007, 2009 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include "syslogd.h"
#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "msg.h"
#include "module-template.h"
#include "glbl.h"
#include "errmsg.h"
#include "parser.h"
#include "datetime.h"
#include "unicode-helper.h"

MODULE_TYPE_PARSER
MODULE_TYPE_NOKEEP
//MODULE_CNFNAME("pmkeyvalue")
PARSER_NAME("contrib.keyvalue")

/* internal structures
 */
DEF_PMOD_STATIC_DATA
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)
DEFobjCurrIf(parser)
DEFobjCurrIf(datetime)


/* static data */
static int bParseHOSTNAMEandTAG;	/* cache for the equally-named global param - performance enhancement */


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATUREAutomaticSanitazion)
		iRet = RS_RET_OK;
	if(eFeat == sFEATUREAutomaticPRIParsing)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

/**
 * Parse a 32 bit integer number from a string.
 *
 * \param ppsz Pointer to the Pointer to the string being parsed. It
 *             must be positioned at the first digit. Will be updated 
 *             so that on return it points to the first character AFTER
 *             the integer parsed.
 * \param pLenStr pointer to string length, decremented on exit by
 *                characters processed
 * 		  Note that if an empty string (len < 1) is passed in,
 * 		  the method always returns zero.
 * \retval The number parsed.
 */
static inline int
srSLMGParseInt32(uchar** ppsz, int *pLenStr)
{
	register int i;

	i = 0;
	while(*pLenStr > 0 && **ppsz >= '0' && **ppsz <= '9') {
		i = i * 10 + **ppsz - '0';
		++(*ppsz);
		--(*pLenStr);
	}

	return i;
}

/**
 * Parse a TIMESTAMP-3339-like (optional timezone).
 * updates the parse pointer position. The pTime parameter
 * is guranteed to be updated only if a new valid timestamp
 * could be obtained (restriction added 2008-09-16 by rgerhards).
 * This method now also checks the maximum string length it is passed.
 * If a *valid* timestamp is found, the string length is decremented
 * by the number of characters processed. If it is not a valid timestamp,
 * the length is kept unmodified. -- rgerhards, 2009-09-23
 */
static rsRetVal
Parse_KV_TIMESTAMP(struct syslogTime *pTime, uchar** ppszTS, int *pLenStr)
{
	uchar *pszTS = *ppszTS;
	/* variables to temporarily hold time information while we parse */
	int year;
	int month;
	int day;
	int hour; /* 24 hour clock */
	int minute;
	int second;
	int secfrac;	/* fractional seconds (must be 32 bit!) */
	int secfracPrecision;
	char OffsetMode;	/* UTC offset + or - */
	char OffsetHour;	/* UTC offset in hours */
	int OffsetMinute;	/* UTC offset in minutes */
	int lenStr;
	/* end variables to temporarily hold time information while we parse */
	DEFiRet;

	assert(pTime != NULL);
	assert(ppszTS != NULL);
	assert(pszTS != NULL);

	lenStr = *pLenStr;
	year = srSLMGParseInt32(&pszTS, &lenStr);

	/* We take the liberty to accept slightly malformed timestamps e.g. in 
	 * the format of 2003-9-1T1:0:0. This doesn't hurt on receiving. Of course,
	 * with the current state of affairs, we would never run into this code
	 * here because at postion 11, there is no "T" in such cases ;)
	 */
	if(lenStr == 0 || *pszTS++ != '-')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	month = srSLMGParseInt32(&pszTS, &lenStr);
	if(month < 1 || month > 12)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != '-')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	day = srSLMGParseInt32(&pszTS, &lenStr);
	if(day < 1 || day > 31)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != 'T')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;

	hour = srSLMGParseInt32(&pszTS, &lenStr);
	if(hour < 0 || hour > 23)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != ':')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	minute = srSLMGParseInt32(&pszTS, &lenStr);
	if(minute < 0 || minute > 59)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != ':')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	second = srSLMGParseInt32(&pszTS, &lenStr);
	if(second < 0 || second > 60)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
 
        DBGPRINTF("DATE & TIME PARSED\n");
	/* Now let's see if we have secfrac */
	if(lenStr > 0 && *pszTS == '.') {
		--lenStr;
		uchar *pszStart = ++pszTS;
		secfrac = srSLMGParseInt32(&pszTS, &lenStr);
		secfracPrecision = (int) (pszTS - pszStart);
	} else {
		secfracPrecision = 0;
		secfrac = 0;
	}

	/* check the timezone */
	// allow for local time (without timezone info)
	if (lenStr == 0 || *pszTS == '\0' || *pszTS == ' ') {
		OffsetMode = 'L';
	} else if(*pszTS == 'Z') {
		--lenStr;
		pszTS++; /* eat Z */
		OffsetMode = 'Z';
		OffsetHour = 0;
		OffsetMinute = 0;
	} else if((*pszTS == '+') || (*pszTS == '-')) {
		OffsetMode = *pszTS;
		--lenStr;
		pszTS++;

		OffsetHour = srSLMGParseInt32(&pszTS, &lenStr);
		if(OffsetHour < 0 || OffsetHour > 23)
			ABORT_FINALIZE(RS_RET_INVLD_TIME);

		if(lenStr == 0 || *pszTS != ':')
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		--lenStr;
		pszTS++;
		OffsetMinute = srSLMGParseInt32(&pszTS, &lenStr);
		if(OffsetMinute < 0 || OffsetMinute > 59)
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
	} else {
		/* there MUST be TZ information */
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	}

	/* OK, we actually have a 3339 timestamp, so let's indicated this */
	if(lenStr > 0) {
		if(*pszTS != ' ' && *pszTS != '\0' ) /* if it is not a space, it can not be a "good" time - 2010-02-22 rgerhards */
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		++pszTS; /* just skip past it */
		--lenStr;
	}

	/* we had success, so update parse pointer and caller-provided timestamp */
	*ppszTS = pszTS;
	pTime->year = year;
	pTime->month = month;
	pTime->day = day;
	pTime->hour = hour;
	pTime->minute = minute;
	pTime->second = second;
	pTime->secfrac = secfrac;
	pTime->secfracPrecision = secfracPrecision;
	if ( OffsetMode == '+' || OffsetMode == '-' || OffsetMode == 'Z' ) {
		pTime->timeType = 2;
		pTime->OffsetMode = OffsetMode;
		pTime->OffsetHour = OffsetHour;
		pTime->OffsetMinute = OffsetMinute;
	} else if (pTime->timeType==0) {
		pTime->timeType = 1;
		pTime->OffsetMode = '\0';
	}
	*pLenStr = lenStr;

finalize_it:
	RETiRet;
}

/* utility functions invoked by parser */

enum PARSEKVSTATES { PKV_INIT, PKV_NAME, PKV_VALUE };

struct _field_parsing {
	uchar name[256];
	uchar value[4096];
	int numericValue;
	int numSignNotAllowed;
	int numDotNotAllowed;
	int numFoundZero;
	int numZeroLeading;
	uchar date[20];
	uchar time[20];
};

static void _save_json_value(json_object *out, struct _field_parsing *pfp) {
	json_object *new_item;
	if (pfp->value[0]=='\0')
		pfp->numericValue = FALSE;;
	if (pfp->numericValue && pfp->numZeroLeading && pfp->value[1]=='\0')
		pfp->numZeroLeading = FALSE;
	if (strstr((const char*)(pfp->name), "id") == NULL && pfp->numericValue && !pfp->numZeroLeading) {
		char *unused;
		if (pfp->numDotNotAllowed) {
			new_item = json_object_new_double(strtod((const char*)(pfp->value), &unused));
		} else {
			new_item = json_object_new_int64(strtoll((const char*)(pfp->value),&unused,10));
		}
	}
	else
		new_item = json_object_new_string((const char*)(pfp->value));
	json_object_object_add(out, (const char*)(pfp->name), new_item);
}

static int parseKV (const uchar* str, int strsize, json_object *out) {
	struct _field_parsing fp;
	const uchar *in;
	uchar *nm=fp.name, *vl=fp.value;
	int inQuotes=FALSE;
	int inDoubleQuotes=FALSE;
	int inEscape=FALSE;
	int doCopy=FALSE, doSave=FALSE;
	enum PARSEKVSTATES state = PKV_INIT;

	in=str;
	while (*in!='\0' && strsize>0) {
		doCopy = FALSE;
		doSave = FALSE;
		switch (*in) {
		case '"':
			if (inEscape) {
				inEscape = FALSE;
				doCopy = TRUE;
			} else if (inQuotes) {
				inQuotes = FALSE;
				inDoubleQuotes = TRUE;
			} else if (inDoubleQuotes) {
				inDoubleQuotes = FALSE;
				inQuotes = TRUE;
				doCopy = TRUE;
			} else {
				inQuotes = TRUE;
			}
			break;
		case '\\':
			if (inEscape) {
				inEscape = FALSE;
				doCopy = TRUE;
			} else {
				inEscape = TRUE;
			}
			break;
		case '=':
			if (inEscape) {
				inEscape = FALSE;
				doCopy = TRUE;
			} else if (inQuotes) {
				doCopy = TRUE;
			} else if (state==PKV_NAME) {
				*nm = '\0';
				state=PKV_VALUE;
			} else {
				// WARNING: should be a syntax error !!!
				doCopy = TRUE;
			}

			break;
		case ' ':
		case '\t':
			if (inEscape) {
				inEscape = FALSE;
				doCopy = TRUE;
			} else if (inQuotes) {
				doCopy = TRUE;
			} else if (state==PKV_VALUE) {
				*vl = '\0';
				state = PKV_INIT;
				doSave = TRUE;
			} else if (state==PKV_NAME) {
				*nm = '\0';
				*vl = '\0';
				state = PKV_INIT;
				doSave = TRUE;
			}
			break;
		case '\r':
		case '\n':
			if (inEscape) {
				inEscape = FALSE;
			} else if (inQuotes) {
				doCopy = TRUE;
			} else if (state==PKV_VALUE) {
				*vl = '\0';
				state = PKV_INIT;
				doSave = TRUE;
			} else if (state==PKV_NAME) {
				*nm = '\0';
				*vl = '\0';
				state = PKV_INIT;
				doSave = TRUE;
			}
			break;
		default:
			if (inEscape) {
				inEscape = FALSE;
			}
			if (inDoubleQuotes) {
				inQuotes=FALSE;
				inDoubleQuotes=FALSE;
			}
			if (state==PKV_INIT) {
				state=PKV_NAME;
				nm = fp.name;
				vl = fp.value;
				fp.numericValue=TRUE;
				fp.numSignNotAllowed=FALSE;
				fp.numDotNotAllowed=FALSE;
				fp.numFoundZero=0;
				fp.numZeroLeading = TRUE;
			}
			doCopy = TRUE;
			break;
		}
		if (doSave && fp.name[0]!='\0') {
			_save_json_value(out,&fp);
			fp.name[0] = '\0';
		}
		if (doCopy) {
			switch (state) {
			case PKV_NAME:
				*nm++ = *in;
				break;
			case PKV_VALUE:
				if (fp.numericValue) {
					switch (*in) {
					case '-':
					case '+':
						if (fp.numSignNotAllowed)
							fp.numericValue = FALSE;
						else
							fp.numSignNotAllowed = TRUE;
						break;
					case '.':
						if (fp.numDotNotAllowed)
							fp.numericValue = FALSE;
						else
							fp.numDotNotAllowed = TRUE;
						fp.numSignNotAllowed = TRUE;
						break;
					case '0':
						if (fp.numZeroLeading)
							fp.numFoundZero++;
						fp.numSignNotAllowed = TRUE;
						break;
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						if (!fp.numFoundZero && !fp.numDotNotAllowed) {
							fp.numZeroLeading = FALSE;
						}
						fp.numFoundZero = 0;
						fp.numSignNotAllowed = TRUE;
						break;
					default:
						fp.numericValue = FALSE;
					}
				}
				*vl++ = *in;
				break;
			default:
				break;
			}
		}

		in++;
		strsize--;
	}
	*nm = '\0';
	*vl = '\0';
	if (fp.name[0]!='\0') {
		_save_json_value(out,&fp);
	}
	return 0;
}



/* parse a key-value formatted syslog message.
 */
BEGINparse
	uchar *p2parse;
	int lenMsg;
	//int bTAGCharDetected;
	//int i;	/* general index for parsing */
	//uchar bufParseTAG[CONF_TAG_MAXSIZE];
	//uchar bufParseHOSTNAME[CONF_HOSTNAME_MAXSIZE];
	uchar *pBuf = NULL;
	json_object *my_root;
CODESTARTparse
	DBGPRINTF("Message will now be parsed by the key-value parser.\n");
	assert(pMsg != NULL);
	assert(pMsg->pszRawMsg != NULL);
	lenMsg = pMsg->iLenRawMsg - pMsg->offAfterPRI; /* note: offAfterPRI is already the number of PRI chars (do not add one!) */
	p2parse = pMsg->pszRawMsg + pMsg->offAfterPRI; /* point to start of text, after PRI */
	setProtocolVersion(pMsg, MSG_LEGACY_PROTOCOL);

	CHKmalloc(pBuf = MALLOC(sizeof(uchar) * (lenMsg + 1)));

	/* KeyValuePairs */
	my_root = json_object_new_object();
	parseKV(p2parse, lenMsg, my_root);

	DBGPRINTF("before parser: timestamp type: %d\n",pMsg->tTIMESTAMP.timeType);
#define _KV_TSLEN 30
	char timestamp[_KV_TSLEN];
	json_object *dtfield, *tmfield;
	uchar *_pUnused = (uchar*)timestamp;
	int _iUnused= _KV_TSLEN;
	timestamp[0] = '\0';
	if (json_object_object_get_ex(my_root, "date", &dtfield)) {
		strncpy(timestamp, json_object_get_string(dtfield), _KV_TSLEN-2);
	}
	if (json_object_object_get_ex(my_root, "time", &tmfield)) {
		if (timestamp[0] != '\0')
			strcat(timestamp, "T" );
		strncat(timestamp, json_object_get_string(tmfield), _KV_TSLEN-1-strlen(timestamp));
	}
	DBGPRINTF("KV timestamp: %s\n",timestamp);
	json_object_object_add(my_root, "eventDate", json_object_new_string(timestamp));
	if (Parse_KV_TIMESTAMP(&(pMsg->tTIMESTAMP), &_pUnused, &_iUnused) == RS_RET_OK) {
		DBGPRINTF("after parser: timestamp type: %d\n",pMsg->tTIMESTAMP.timeType);
		if(pMsg->tTIMESTAMP.timeType==1 && pMsg->dfltTZ[0] != '\0') {
			DBGPRINTF("applied default TZ\n");
			applyDfltTZ(&pMsg->tTIMESTAMP, pMsg->dfltTZ);
		}
		DBGPRINTF("KV timestamp parsed\n");
	}
	msgAddJSON(pMsg, (uchar*)"!", my_root);
	iRet = RS_RET_OK;


finalize_it:
	if(pBuf != NULL)
		free(pBuf);
ENDparse


BEGINmodExit
CODESTARTmodExit
	/* release what we no longer need */
	objRelease(errmsg, CORE_COMPONENT);
	objRelease(glbl, CORE_COMPONENT);
	objRelease(parser, CORE_COMPONENT);
	objRelease(datetime, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_PMOD_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	CHKiRet(objUse(parser, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));

	DBGPRINTF("key/value parser init called\n");
 	bParseHOSTNAMEandTAG = glbl.GetParseHOSTNAMEandTAG(); /* cache value, is set only during rsyslogd option processing */


ENDmodInit

/* vim:set ai:
 */
