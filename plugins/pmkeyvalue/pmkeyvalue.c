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
