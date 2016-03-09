/* omjournal.c
 * send messages to the Linux Journal. This is meant to be used
 * in cases where journal serves as the whole system log database.
 * Note that we may get into a loop if journald re-injects messages
 * into the syslog stream and we read that via imuxsock. Thus there
 * is an option in imuxsock to ignore messages from ourselves 
 * (actually from our pid). So there are some module-interdependencies.
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
#include "conf.h"
#include "cfsysline.h"
#include <json.h>
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include <systemd/sd-journal.h>
#include "unicode-helper.h"
#include <sys/uio.h>

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omjournal")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* config variables */


typedef struct _instanceData {
    uchar *tplName;
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
	{ "template", eCmdHdlrGetWord, 0 }
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};


struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
};
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
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
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
    free(pData->tplName);
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance

static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->tplName = NULL;
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	DBGPRINTF("newActInst (mmjournal)\n");
	pvals = nvlstGetParams(lst, &actpblk, NULL);

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	CODE_STD_STRING_REQUESTnewActInst(1)
	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
    		continue;

        if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("ommongodb: program error, non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
    }

	if(pData->tplName == NULL) {
		CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	} else {
		CHKiRet(OMSRsetEntry(*ppOMSR, 0, ustrdup(pData->tplName),
				     OMSR_TPL_AS_JSON));
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


struct iovec *
build_iovec(size_t *argc, struct json_object *json) {

    struct lh_entry *entry ;
    struct iovec *iov;
    const char *key;
    const char *val;
    size_t key_len;
    size_t val_len;
    size_t vec_len;
    size_t i;

    *argc = json_object_object_length(json);
    iov = malloc( sizeof(struct iovec) * *argc );
    entry = json_object_get_object(json)->head;

    if(NULL == iov)
        goto fail;

    /* 
     * we have to avoid using json_object_object_foreachC because clang static analyzer doesn't believe
     * that I've correct initialised all the elements of iov.
     * I'm assuming that json_object_object_length isn't lying to me, and that the json object isn't
     * changing under my feet so that we can do an explicit `for` iteration instead of just walking the
     * the linked list.
     */

    for(i = 0; i < *argc; i++)
    {
        key = (char *)entry->k;
        val = json_object_get_string((struct json_object*)entry->v);

        key_len = strlen(key);
        val_len = strlen(val);
        // vec length is len(key=val)
        vec_len = key_len + val_len + 1;

        char *buf = malloc(vec_len + 1);
        if(NULL == buf) 
            goto fail;
       
        memcpy(buf, key, key_len);
        memcpy(buf + key_len, "=", 1);
        memcpy(buf + key_len + 1, val, val_len+1);

        iov[i].iov_base = buf;
        iov[i].iov_len = vec_len;

        entry = entry->next;
    }
    return iov;

fail:
    if( NULL == iov)
        return NULL;

    size_t j;
    // iterate over any iovecs that were initalised above and free them.
    for(j = 0; j < i; j++)
    {
        free(iov[j].iov_base);
    }

    free(iov);
    return NULL;
}


void
send_non_template_message(msg_t *pMsg) {
  uchar *tag;
  int lenTag;
  int sev;  

  MsgGetSeverity(pMsg, &sev);
  getTAG(pMsg, &tag, &lenTag);
  /* we can use more properties here, but let's see if there
   *   * is some real user interest. We can always add later...
   *       */
   sd_journal_send("MESSAGE=%s", getMSG(pMsg),
       "PRIORITY=%d", sev,
       "SYSLOG_FACILITY=%d", pMsg->iFacility,
       "SYSLOG_IDENTIFIER=%s", tag,
       NULL);

}

void
send_template_message(struct json_object* json){

    size_t argc;
    struct iovec *iovec;
    size_t i;

    iovec = build_iovec(&argc,  json);
    if( NULL != iovec) {
        sd_journal_sendv(iovec, argc);
        for (i =0; i< argc; i++)
            free(iovec[i].iov_base);
        free(iovec);
    }

}

BEGINdoAction
    instanceData *pData;
CODESTARTdoAction

	pData = pWrkrData->pData;

    if (pData->tplName == NULL) {   
        send_non_template_message((msg_t*) ppString[0]);
     }
    else {
        send_template_message((struct json_object*) ppString[0]);
    }
 ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(!strncmp((char*) p, ":omjournal:", sizeof(":omjournal:") - 1)) {
		errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
			"omjournal supports only v6+ config format, use: "
			"action(type=\"omjournal\" ...)");
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
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	DBGPRINTF("omjournal: module compiled with rsyslog version %s.\n", VERSION);
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
ENDmodInit


