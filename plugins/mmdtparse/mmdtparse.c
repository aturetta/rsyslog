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

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmdtparse")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* config variables */

typedef struct _instanceData {
	char fieldname[CONF_HOSTNAME_MAXSIZE];
} instanceData;

struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
};
static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "field", eCmdHdlrGetWord, 0 },
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
 */
static rsRetVal
Parse_loose_TIMESTAMP(struct syslogTime *pTime, uchar** ppszTS, int *pLenStr)
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


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
ENDfreeInstance


static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->fieldname[0] = '\0';
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
		if(!strcmp(actpblk.descr[i].name, "field")) {
			char * tmpStr = es_str2cstr(pvals[i].val.d.estr,NULL);
			if (tmpStr != NULL) {
				strncpy (tmpStr, pData->fieldname, sizeof(pData->fieldname));
				free(tmpStr);
			}
		} else {
			dbgprintf("mmadtformat: program error, non-handled "
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
	//int i;
CODESTARTdoAction
	pMsg = (msg_t*) ppString[0];
	lenMsg = getMSGLen(pMsg);
	msg = getMSG(pMsg);
	//for(i = 0 ; i < lenMsg ; ++i) {
	//	anonip(pData, msg, &lenMsg, &i);
	//}

//	DBGPRINTF("before parser: timestamp type: %d\n",pMsg->tTIMESTAMP.timeType);
//#define _KV_TSLEN 30
//	char timestamp[_KV_TSLEN];
//	json_object *dtfield, *tmfield;
//	uchar *_pUnused = (uchar*)timestamp;
//	int _iUnused= _KV_TSLEN;
//	timestamp[0] = '\0';
//	if (json_object_object_get_ex(my_root, "date", &dtfield)) {
//		strncpy(timestamp, json_object_get_string(dtfield), _KV_TSLEN-2);
//	}
//	if (json_object_object_get_ex(my_root, "time", &tmfield)) {
//		if (timestamp[0] != '\0')
//			strcat(timestamp, "T" );
//		strncat(timestamp, json_object_get_string(tmfield), _KV_TSLEN-1-strlen(timestamp));
//	}
//	DBGPRINTF("KV timestamp: %s\n",timestamp);
//	json_object_object_add(my_root, "eventDate", json_object_new_string(timestamp));
//	if (Parse_KV_TIMESTAMP(&(pMsg->tTIMESTAMP), &_pUnused, &_iUnused) == RS_RET_OK) {
//		DBGPRINTF("after parser: timestamp type: %d\n",pMsg->tTIMESTAMP.timeType);
//		if(pMsg->tTIMESTAMP.timeType==1 && pMsg->dfltTZ[0] != '\0') {
//			DBGPRINTF("applied default TZ\n");
//			applyDfltTZ(&pMsg->tTIMESTAMP, pMsg->dfltTZ);
//		}
//		DBGPRINTF("KV timestamp parsed\n");
//	}

	if(lenMsg != getMSGLen(pMsg))
		setMSGLen(pMsg, lenMsg);
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
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	DBGPRINTF("mmdtparse: module compiled with rsyslog version %s.\n", VERSION);
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
ENDmodInit
