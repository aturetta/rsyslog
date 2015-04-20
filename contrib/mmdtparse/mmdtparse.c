/* mmdtparse.c
 * parse additional date formats, optionally from user fields
 *
 * Copyright 2013 Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "datetime.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmdtparse")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* config variables */

typedef struct _instanceData {
	char srcField[CONF_HOSTNAME_MAXSIZE];
	char dstField[CONF_HOSTNAME_MAXSIZE];
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
};
static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "source", eCmdHdlrGetWord, 0 },
	{ "destination", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};

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
 *
 * Code borrowed from datetime.c (ParseTIMESTAMP3339)
 */
static rsRetVal
ParseTIMESTAMP_loose(struct syslogTime *pTime, uchar** ppszTS, int *pLenStr)
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
 
        //DBGPRINTF("DATE & TIME PARSED\n");
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

/**
 * Parse a apache/httpd timestamp. The pTime parameter
 * is guranteed to be updated only if a new valid timestamp
 * could be obtained (restriction added 2008-09-16 by rgerhards). This
 * also means the caller *must* provide a valid (probably current) 
 * timstamp in pTime when calling this function. a 3164 timestamp contains
 * only partial information and only that partial information is updated.
 * So the "output timestamp" is a valid timestamp only if the "input
 * timestamp" was valid, too. The is actually an optimization, as it
 * permits us to use a pre-aquired timestamp and thus avoids to do
 * a (costly) time() call. Thanks to David Lang for insisting on
 * time() call reduction ;).
 * This method now also checks the maximum string length it is passed.
 * If a *valid* timestamp is found, the string length is decremented
 * by the number of characters processed. If it is not a valid timestamp,
 * the length is kept unmodified. -- rgerhards, 2009-09-23
 *
 * Code borrowed from datetime.c (ParseTIMESTAMP3164)
 */
static rsRetVal
ParseTIMESTAMP_Apache(struct syslogTime *pTime, uchar** ppszTS, int *pLenStr)
{
	/* variables to temporarily hold time information while we parse */
	int month;
	int day;
	int year = 0; /* 0 means no year provided */
	int hour; /* 24 hour clock */
	int minute;
	int second;
	char OffsetMode;	/* UTC offset + or - */
	char OffsetHour;	/* UTC offset in hours */
	int OffsetMinute;	/* UTC offset in minutes */
	int secfrac;	/* fractional seconds (must be 32 bit!) */
	int secfracPrecision;
	/* end variables to temporarily hold time information while we parse */
	int lenStr;
	uchar *pszTS;
	DEFiRet;

	assert(ppszTS != NULL);
	pszTS = *ppszTS;
	assert(pszTS != NULL);
	assert(pTime != NULL);
	assert(pLenStr != NULL);
	lenStr = *pLenStr;

	/* we accept a slightly malformed timestamp when receiving. This is
	 * we accept one-digit days
	 */
	while((*pszTS == ' ' || *pszTS == '[') && lenStr>0) {
		--lenStr;
		++pszTS;
	}

	day = srSLMGParseInt32(&pszTS, &lenStr);
	if(day < 1 || day > 31)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != '/')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;

	//DBGPRINTF("DTPARSE: day parsed %d\n",day);
	/* If we look at the month (Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec),
	 * we may see the following character sequences occur:
	 *
	 * J(an/u(n/l)), Feb, Ma(r/y), A(pr/ug), Sep, Oct, Nov, Dec
	 *
	 * We will use this for parsing, as it probably is the
	 * fastest way to parse it.
	 *
	 * we do case-insensitive comparisons
	 */
	if(lenStr < 3)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	switch(*pszTS++)
	{
	case 'j':
	case 'J':
		if(*pszTS == 'a' || *pszTS == 'A') {
			++pszTS;
			if(*pszTS == 'n' || *pszTS == 'N') {
				++pszTS;
				month = 1;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else if(*pszTS == 'u' || *pszTS == 'U') {
			++pszTS;
			if(*pszTS == 'n' || *pszTS == 'N') {
				++pszTS;
				month = 6;
			} else if(*pszTS == 'l' || *pszTS == 'L') {
				++pszTS;
				month = 7;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'f':
	case 'F':
		if(*pszTS == 'e' || *pszTS == 'E') {
			++pszTS;
			if(*pszTS == 'b' || *pszTS == 'B') {
				++pszTS;
				month = 2;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'm':
	case 'M':
		if(*pszTS == 'a' || *pszTS == 'A') {
			++pszTS;
			if(*pszTS == 'r' || *pszTS == 'R') {
				++pszTS;
				month = 3;
			} else if(*pszTS == 'y' || *pszTS == 'Y') {
				++pszTS;
				month = 5;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'a':
	case 'A':
		if(*pszTS == 'p' || *pszTS == 'P') {
			++pszTS;
			if(*pszTS == 'r' || *pszTS == 'R') {
				++pszTS;
				month = 4;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else if(*pszTS == 'u' || *pszTS == 'U') {
			++pszTS;
			if(*pszTS == 'g' || *pszTS == 'G') {
				++pszTS;
				month = 8;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 's':
	case 'S':
		if(*pszTS == 'e' || *pszTS == 'E') {
			++pszTS;
			if(*pszTS == 'p' || *pszTS == 'P') {
				++pszTS;
				month = 9;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'o':
	case 'O':
		if(*pszTS == 'c' || *pszTS == 'C') {
			++pszTS;
			if(*pszTS == 't' || *pszTS == 'T') {
				++pszTS;
				month = 10;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'n':
	case 'N':
		if(*pszTS == 'o' || *pszTS == 'O') {
			++pszTS;
			if(*pszTS == 'v' || *pszTS == 'V') {
				++pszTS;
				month = 11;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	case 'd':
	case 'D':
		if(*pszTS == 'e' || *pszTS == 'E') {
			++pszTS;
			if(*pszTS == 'c' || *pszTS == 'C') {
				++pszTS;
				month = 12;
			} else
				ABORT_FINALIZE(RS_RET_INVLD_TIME);
		} else
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		break;
	default:
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	}

	lenStr -= 3;

	//DBGPRINTF("DTPARSE: month parsed %d\n",month);
	/* done month */

	if(lenStr == 0 || *pszTS++ != '/')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	year = srSLMGParseInt32(&pszTS, &lenStr);
	//DBGPRINTF("DTPARSE: year parsed %d\n",year);

	/* hour part */
	if(lenStr == 0 || *pszTS++ != ':')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	hour = srSLMGParseInt32(&pszTS, &lenStr);

	//DBGPRINTF("DTPARSE: hour parsed %d\n",hour);
	if(hour < 0 || hour > 23)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != ':')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	minute = srSLMGParseInt32(&pszTS, &lenStr);
	//DBGPRINTF("DTPARSE: minute parsed %d\n",minute);
	if(minute < 0 || minute > 59)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

	if(lenStr == 0 || *pszTS++ != ':')
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	--lenStr;
	second = srSLMGParseInt32(&pszTS, &lenStr);
	//DBGPRINTF("DTPARSE: second parsed %d\n",second);
	if(second < 0 || second > 60)
		ABORT_FINALIZE(RS_RET_INVLD_TIME);

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

	while((*pszTS == ' ' || *pszTS == 'T') && lenStr>0) {
		--lenStr;
		++pszTS;
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
		//DBGPRINTF("DTPARSE: offset hour parsed %d\n",OffsetHour);
		if(OffsetHour < 0 || (OffsetHour > 23 && OffsetHour<30))
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
		if(OffsetHour >=30) {
			OffsetMinute = OffsetHour%100;
			OffsetHour /= 100;
		} else {
			if(lenStr > 0 && *pszTS == ':') {
				--lenStr;
				pszTS++;
			}
			OffsetMinute = srSLMGParseInt32(&pszTS, &lenStr);
			//DBGPRINTF("DTPARSE: offset minute parsed %d\n",OffsetMinute);
		}
		if(OffsetMinute < 0 || OffsetMinute > 59)
			ABORT_FINALIZE(RS_RET_INVLD_TIME);
	} else {
		/* there MUST be TZ information */
		ABORT_FINALIZE(RS_RET_INVLD_TIME);
	}

	/* we had success, so update parse pointer and caller-provided timestamp
	 * fields we do not have are not updated in the caller's timestamp. This
	 * is the reason why the caller must pass in a correct timestamp.
	 */
	*ppszTS = pszTS; /* provide updated parse position back to caller */
	pTime->month = month;
	if(year > 0)
		pTime->year = year; /* persist year if detected */
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

void
applyDfltTZ(struct syslogTime *pTime, char *tz)
{
	pTime->OffsetMode = tz[0];
	pTime->OffsetHour = (tz[1] - '0') * 10 + (tz[2] - '0');
	pTime->OffsetMinute = (tz[4] - '0') * 10 + (tz[5] - '0');

}

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance


static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->srcField[0] = '\0';
	pData->dstField[0] = '\0';
}

static inline void
saveParamString(es_str_t* pPar, char* dst, es_size_t maxLen) {
	char * tmpStr = es_str2cstr(pPar,NULL);
	if (tmpStr != NULL) {
		strncpy (dst, tmpStr, maxLen);
		free(tmpStr);
	}
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	DBGPRINTF("newActInst (mmdtparse)\n");
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(actpblk.descr[i].name, "source")) {
			saveParamString(pvals[i].val.d.estr, pData->srcField, sizeof(pData->srcField)-1);
		} else if(!strcmp(actpblk.descr[i].name, "destination")) {
			saveParamString(pvals[i].val.d.estr, pData->dstField, sizeof(pData->dstField)-1);
		} else {
			dbgprintf("mmdtparse: program error, non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
	}


CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
ENDtryResume


BEGINdoAction
	msg_t *pMsg;
	uchar *msg;
	int lenMsg;
	int bSuccess;
	instanceData *pData = pWrkrData->pData;
	//int i;
CODESTARTdoAction
	bSuccess = 0;
	pMsg = (msg_t*) ppString[0];
	//lenMsg = getMSGLen(pMsg);
	//msg = getMSG(pMsg);
	//for(i = 0 ; i < lenMsg ; ++i) {
	//	anonip(pData, msg, &lenMsg, &i);
	//}

	DBGPRINTF("before DTPARSE: source: %s\n",pData->srcField)
//#define _KV_TSLEN 30
	json_object *dst;
	msgPropDescr_t cSource;
	unsigned short bMustBeFreed=FALSE;
	uchar *pVal=NULL;

	if (pData->srcField[0]!='\0') {
		CHKiRet(msgPropDescrFill(&cSource, (uchar*)pData->srcField, strlen(pData->srcField)));
	} else {
		CHKiRet(msgPropDescrFill(&cSource, (uchar*)"msg", 3));
	}
	pVal = (uchar*) MsgGetProp(pMsg, NULL, &cSource, &lenMsg, &bMustBeFreed, NULL);

	DBGPRINTF("DTPARSE source timestamp: %s\n",pVal);
	msg = pVal;
	struct syslogTime *pRes = &(pMsg->tTIMESTAMP);
	// TODO: manage destination field
	if (ParseTIMESTAMP_loose(pRes, &msg, &lenMsg) == RS_RET_OK) {
		DBGPRINTF("DTPARSE: loose-3339 timestamp parsed\n");
		bSuccess = 1;
	} else if (ParseTIMESTAMP_Apache(pRes, &msg, &lenMsg) == RS_RET_OK) {
		DBGPRINTF("DTPARSE: apache timestamp parsed\n");
		bSuccess = 1;
	} else {
		DBGPRINTF("DTPARSE: timestamp not parsed\n");
	}
	if(pRes->timeType==1 && pMsg->dfltTZ[0] != '\0') {
		DBGPRINTF("DTPARSE: applied default TZ\n");
		applyDfltTZ(pRes, pMsg->dfltTZ);
	}

finalize_it:
	MsgSetParseSuccess(pMsg, bSuccess);
	if (bMustBeFreed)
		free(pVal);
ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(strncmp((char*) p, ":mmdtparse:", sizeof(":mmdtparse:") - 1)) {
		errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
			"mmdtparse supports only v6+ config format, use: "
			"action(type=\"mmdtparse\" ...)");
	}
	ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
	objRelease(errmsg, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	DBGPRINTF("mmdtparse: module compiled with rsyslog version %s.\n", VERSION);
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
ENDmodInit
