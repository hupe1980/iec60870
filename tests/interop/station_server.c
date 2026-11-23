/*
 * station-server: lib60870-C's controlled station serving a fixed point table, answering
 * interrogation, counter interrogation, read, clock synchronisation and commands (direct and
 * select-before-operate), for the iec60870 crate's Client in the interop tests.
 *
 * Part of the iec60870 crate's test suite. Licensed MIT OR Apache-2.0, like the crate.
 * It links against lib60870-C (GPL-3), which Dockerfile.station clones at a pinned commit.
 *
 * usage: station-server -p PORT [--duration MS]
 *
 * CA 1: M_SP_NA_1 IOA 100 = ON, M_ME_NB_1 IOA 101 = -7, M_ME_NC_1 IOA 200 = 21.5,
 * M_IT_NA_1 IOA 300 = 1234. Commands at any IOA 5000-5999 are confirmed and (execute)
 * terminated; any other IOA is answered with COT 47. After the first interrogation, one
 * spontaneous M_SP_TB_1 IOA 100 = OFF is sent.
 * Prints READY, then COMMAND <type> <ioa> <select> | CLOCK | GI | CI | READ <ioa> per request.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INTEROP_TLS
#include "tls_peer.h"
#endif

#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"

static CS104_Slave slave;
static volatile bool spontaneous = false;

static CS101_ASDU
new_asdu(IMasterConnection con, CS101_CauseOfTransmission cot)
{
    return CS101_ASDU_create(IMasterConnection_getApplicationLayerParameters(con), false, cot, 0, 1, false, false);
}

static bool
gi_handler(void* p, IMasterConnection con, CS101_ASDU asdu, uint8_t qoi)
{
    (void)p;
    printf("GI %d\n", qoi);
    IMasterConnection_sendACT_CON(con, asdu, false);
    if (qoi == IEC60870_QOI_STATION) {
        CS101_ASDU a = new_asdu(con, CS101_COT_INTERROGATED_BY_STATION);
        InformationObject io = (InformationObject)SinglePointInformation_create(NULL, 100, true, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        IMasterConnection_sendASDU(con, a);
        CS101_ASDU_destroy(a);
        a = new_asdu(con, CS101_COT_INTERROGATED_BY_STATION);
        io = (InformationObject)MeasuredValueScaled_create(NULL, 101, -7, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        IMasterConnection_sendASDU(con, a);
        CS101_ASDU_destroy(a);
        a = new_asdu(con, CS101_COT_INTERROGATED_BY_STATION);
        io = (InformationObject)MeasuredValueShort_create(NULL, 200, 21.5f, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        IMasterConnection_sendASDU(con, a);
        CS101_ASDU_destroy(a);
    }
    IMasterConnection_sendACT_TERM(con, asdu);
    spontaneous = true;
    return true;
}

static bool
ci_handler(void* p, IMasterConnection con, CS101_ASDU asdu, QualifierOfCIC qcc)
{
    (void)p;
    printf("CI %d\n", qcc);
    IMasterConnection_sendACT_CON(con, asdu, false);
    CS101_ASDU a = new_asdu(con, CS101_COT_REQUESTED_BY_GENERAL_COUNTER);
    BinaryCounterReading bcr = BinaryCounterReading_create(NULL, 1234, 0, false, false, false);
    InformationObject io = (InformationObject)IntegratedTotals_create(NULL, 300, bcr);
    CS101_ASDU_addInformationObject(a, io);
    InformationObject_destroy(io);
    BinaryCounterReading_destroy(bcr);
    IMasterConnection_sendASDU(con, a);
    CS101_ASDU_destroy(a);
    IMasterConnection_sendACT_TERM(con, asdu);
    return true;
}

static bool
read_handler(void* p, IMasterConnection con, CS101_ASDU asdu, int ioa)
{
    (void)p;
    (void)asdu;
    printf("READ %d\n", ioa);
    CS101_ASDU a = new_asdu(con, CS101_COT_REQUEST);
    InformationObject io = (InformationObject)MeasuredValueShort_create(NULL, ioa, 21.5f, IEC60870_QUALITY_GOOD);
    CS101_ASDU_addInformationObject(a, io);
    InformationObject_destroy(io);
    IMasterConnection_sendASDU(con, a);
    CS101_ASDU_destroy(a);
    return true;
}

static bool
clock_handler(void* p, IMasterConnection con, CS101_ASDU asdu, CP56Time2a t)
{
    (void)p;
    (void)con;
    (void)asdu;
    printf("CLOCK %d:%02d\n", CP56Time2a_getHour(t), CP56Time2a_getMinute(t));
    return true;
}

static bool
asdu_handler(void* p, IMasterConnection con, CS101_ASDU asdu)
{
    (void)p;
    int type = CS101_ASDU_getTypeID(asdu);
    bool command = (type >= C_SC_NA_1 && type <= C_BO_NA_1) || (type >= C_SC_TA_1 && type <= C_BO_TA_1);
    if (!command)
        return false;
    InformationObject io = CS101_ASDU_getElement(asdu, 0);
    int ioa = io ? InformationObject_getObjectAddress(io) : -1;
    bool select = false;
    if (io) {
        if (type == C_SC_NA_1 || type == C_SC_TA_1) select = SingleCommand_isSelect((SingleCommand)io);
        else if (type == C_DC_NA_1 || type == C_DC_TA_1) select = DoubleCommand_isSelect((DoubleCommand)io);
        else if (type == C_RC_NA_1 || type == C_RC_TA_1) select = StepCommand_isSelect((StepCommand)io);
        else if (type == C_SE_NA_1 || type == C_SE_TA_1) select = SetpointCommandNormalized_isSelect((SetpointCommandNormalized)io);
        else if (type == C_SE_NB_1 || type == C_SE_TB_1) select = SetpointCommandScaled_isSelect((SetpointCommandScaled)io);
        else if (type == C_SE_NC_1 || type == C_SE_TC_1) select = SetpointCommandShort_isSelect((SetpointCommandShort)io);
        InformationObject_destroy(io);
    }
    printf("COMMAND %d %d %d\n", type, ioa, select ? 1 : 0);
    if (CS101_ASDU_getCOT(asdu) != CS101_COT_ACTIVATION) {
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
        CS101_ASDU_setNegative(asdu, true);
        IMasterConnection_sendASDU(con, asdu);
    } else if (ioa < 5000 || ioa > 5999) {
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
        CS101_ASDU_setNegative(asdu, true);
        IMasterConnection_sendASDU(con, asdu);
    } else {
        IMasterConnection_sendACT_CON(con, asdu, false);
        if (!select)
            IMasterConnection_sendACT_TERM(con, asdu);
    }
    return true;
}

#ifdef INTEROP_FILES
#include "cs101_file_service.h"

static int file_size(CS101_IFileProvider file) { (void)file; return 800; }
static uint64_t file_date(CS101_IFileProvider file) { (void)file; return 0; }
static int section_size(CS101_IFileProvider file, int section) { (void)file; return section >= 0 && section < 2 ? 400 : 0; }
static bool copy_record(CS101_IFileProvider file, int section, int offset, int size, uint8_t *data) {
    if (offset < 0 || size < 0 || offset + size > section_size(file, section)) return false;
    for (int i = 0; i < size; ++i) data[i] = (uint8_t)(section * 400 + offset + i);
    return true;
}
static void file_done(CS101_IFileProvider file, bool success) { (void)file; printf("DOWNLOAD %d\n", success); }
static struct sCS101_IFileProvider record = {
    .ca=1, .ioa=30000, .nof=2, .getFileDate=file_date, .getFileSize=file_size, .getSectionSize=section_size,
    .getSegmentData=copy_record, .transferComplete=file_done
};
static CS101_IFileProvider find_record(void *ctx, int ca, int ioa, uint16_t name, int *err) {
    (void)ctx; (void)err; return ca==1 && ioa==30000 && name==2 ? &record : NULL;
}
static CS101_IFileProvider next_record(void *ctx, CS101_IFileProvider previous) { (void)ctx; return previous ? NULL : &record; }
#endif

int
main(int argc, char** argv)
{
    int port = 2404;
    int duration = 30000;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "-p")) port = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--duration")) duration = atoi(argv[i + 1]);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
#ifdef INTEROP_TLS
    TLSConfiguration tls = peer_tls("/pki/server.pem", "/pki/server.key");
    slave = CS104_Slave_createSecure(100, 100, tls);
#else
    slave = CS104_Slave_create(100, 100);
#endif
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
    CS104_Slave_setInterrogationHandler(slave, gi_handler, NULL);
    CS104_Slave_setCounterInterrogationHandler(slave, ci_handler, NULL);
    CS104_Slave_setReadHandler(slave, read_handler, NULL);
    CS104_Slave_setClockSyncHandler(slave, clock_handler, NULL);
    CS104_Slave_setASDUHandler(slave, asdu_handler, NULL);
#ifdef INTEROP_FILES
    CS101_FileServer files = CS101_FileServer_create(CS104_Slave_getAppLayerParameters(slave));
    struct sCS101_FilesAvailable catalog = { .getFile=find_record, .getNextFile=next_record };
    CS101_FileServer_setFilesAvailableIfc(files, &catalog);
    CS104_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(files));
#endif
    CS104_Slave_start(slave);
    if (!CS104_Slave_isRunning(slave)) {
        puts("FAILED");
        return 1;
    }
    puts("READY");
    uint64_t until = Hal_getTimeInMs() + duration;
    bool sent = false;
    while (Hal_getTimeInMs() < until) {
        if (spontaneous && !sent) {
            sent = true;
            Thread_sleep(200);
            CS101_ASDU a = CS101_ASDU_create(CS104_Slave_getAppLayerParameters(slave), false, CS101_COT_SPONTANEOUS, 0, 1, false, false);
            struct sCP56Time2a now;
            CP56Time2a_createFromMsTimestamp(&now, Hal_getTimeInMs());
            InformationObject io = (InformationObject)SinglePointWithCP56Time2a_create(NULL, 100, false, IEC60870_QUALITY_GOOD, &now);
            CS101_ASDU_addInformationObject(a, io);
            InformationObject_destroy(io);
            CS104_Slave_enqueueASDU(slave, a);
            CS101_ASDU_destroy(a);
        }
        Thread_sleep(50);
    }
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
#ifdef INTEROP_FILES
    CS101_FileServer_destroy(files);
#endif
#ifdef INTEROP_TLS
    TLSConfiguration_destroy(tls);
#endif
    puts("EXIT");
    return 0;
}
