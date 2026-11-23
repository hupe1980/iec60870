/*
 * station-client: lib60870-C's controlling station running every station procedure against
 * the iec60870 crate's Server, for the interop tests.
 *
 * Part of the iec60870 crate's test suite. Licensed MIT OR Apache-2.0, like the crate.
 * It links against lib60870-C (GPL-3), which Dockerfile.station clones at a pinned commit.
 *
 * usage: station-client -h HOST -p PORT
 *
 * The outstation is expected to serve CA 1 with the command points of tests/interop_station.rs.
 * Prints one line per event on stdout:
 *   CONNECTED | ACTIVATED | STEP <name> | ASDU <type> <cot> <negative> <ca> <ioa> <count> | EXIT | FAILED
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "hal_thread.h"
#ifdef INTEROP_TLS
#include "tls_peer.h"
static atomic_bool gi_complete, cmd_complete;

static void await_completion(atomic_bool *flag)
{
    for (int i = 0; i < 100 && !atomic_load(flag); ++i)
        Thread_sleep(50);
    if (!atomic_load(flag)) exit(3);
}
#endif

#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"

static volatile bool active = false;
static atomic_bool directory_complete;
static atomic_int file_stage;
static bool await_stage(int stage) {
    for (int i=0; i<100 && atomic_load(&file_stage)<stage; ++i) Thread_sleep(50);
    return atomic_load(&file_stage)==stage;
}
static bool file_message(CS104_Connection con, InformationObject message) {
    bool ok=CS104_Connection_sendProcessCommandEx(con, CS101_COT_FILE_TRANSFER, 1, message);
    InformationObject_destroy(message);
    return ok;
}

static bool
asdu_handler(void* parameter, int address, CS101_ASDU asdu)
{
    (void)parameter;
    (void)address;
    if (CS101_ASDU_getTypeID(asdu) == F_DR_TA_1) {
        for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); ++i) {
            FileDirectory entry = (FileDirectory)CS101_ASDU_getElement(asdu, i);
            if (!entry) return false;
            bool last = FileDirectory_getLFD(entry);
            printf("FILE %d %u %u %d\n", InformationObject_getObjectAddress((InformationObject)entry),
                   (unsigned)FileDirectory_getNOF(entry), (unsigned)FileDirectory_getLengthOfFile(entry), last);
            FileDirectory_destroy(entry);
            if (last) atomic_store(&directory_complete, true);
        }
    }
    int ioa = -1;
    InformationObject io = CS101_ASDU_getElement(asdu, 0);
    if (io) {
        ioa = InformationObject_getObjectAddress(io);
        if (CS101_ASDU_getCOT(asdu)==CS101_COT_FILE_TRANSFER && ioa==1) {
            switch (CS101_ASDU_getTypeID(asdu)) {
            case F_FR_NA_1:
                printf("FILE_READY %u %d\n", (unsigned)FileReady_getFRQ((FileReady)io), FileReady_isPositive((FileReady)io));
                if (FileReady_getFRQ((FileReady)io)==0 && FileReady_getLengthOfFile((FileReady)io)==3) atomic_store(&file_stage,1);
                break;
            case F_SR_NA_1:
                if (SectionReady_getLengthOfSection((SectionReady)io)==3) atomic_store(&file_stage,2);
                break;
            case F_SG_NA_1:
                if (FileSegment_getLengthOfSegment((FileSegment)io)==3 &&
                    memcmp(FileSegment_getSegmentData((FileSegment)io),"\1\2\3",3)==0) atomic_store(&file_stage,3);
                break;
            case F_LS_NA_1: {
                FileLastSegmentOrSection marker=(FileLastSegmentOrSection)io;
                int previous=atomic_load(&file_stage);
                if (FileLastSegmentOrSection_getCHS(marker)==6 &&
                    ((FileLastSegmentOrSection_getLSQ(marker)==3 && previous==3) ||
                     (FileLastSegmentOrSection_getLSQ(marker)==1 && previous==4))) atomic_store(&file_stage,previous+1);
                break;
            }
            default: break;
            }
        }
        InformationObject_destroy(io);
    }
    printf("ASDU %d %d %d %d %d %d\n", (int)CS101_ASDU_getTypeID(asdu), (int)CS101_ASDU_getCOT(asdu), CS101_ASDU_isNegative(asdu) ? 1 : 0,
           CS101_ASDU_getCA(asdu), ioa, CS101_ASDU_getNumberOfElements(asdu));
    fflush(stdout);
#ifdef INTEROP_TLS
    if (!CS101_ASDU_isNegative(asdu) && CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION_TERMINATION) {
        if (CS101_ASDU_getTypeID(asdu) == C_IC_NA_1) atomic_store(&gi_complete, true);
        if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1) atomic_store(&cmd_complete, true);
    }
#endif
    return true;
}

static void
connection_handler(void* parameter, CS104_Connection con, CS104_ConnectionEvent event)
{
    (void)parameter;
    (void)con;
    if (event == CS104_CONNECTION_STARTDT_CON_RECEIVED)
        active = true;
}

static void
step(const char* name)
{
    printf("STEP %s\n", name);
    fflush(stdout);
}

static void
settle(void)
{
    Thread_sleep(400);
}

static void
command(CS104_Connection con, InformationObject io)
{
    CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, io);
    InformationObject_destroy(io);
    settle();
}

/* One command of each kind at its IOA, as select (true) or execute, plain or time-tagged. */
static InformationObject
make(int kind, bool select, bool timed, struct sCP56Time2a* t)
{
    switch (kind) {
    case 0: return timed ? (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 5000, true, select, 0, t)
                         : (InformationObject)SingleCommand_create(NULL, 5000, true, select, 0);
    case 1: return timed ? (InformationObject)DoubleCommandWithCP56Time2a_create(NULL, 5001, 2, select, 0, t)
                         : (InformationObject)DoubleCommand_create(NULL, 5001, 2, select, 0);
    case 2: return timed ? (InformationObject)StepCommandWithCP56Time2a_create(NULL, 5002, IEC60870_STEP_HIGHER, select, 0, t)
                         : (InformationObject)StepCommand_create(NULL, 5002, IEC60870_STEP_HIGHER, select, 0);
    case 3: return timed ? (InformationObject)SetpointCommandNormalizedWithCP56Time2a_create(NULL, 5003, 0.5f, select, 0, t)
                         : (InformationObject)SetpointCommandNormalized_create(NULL, 5003, 0.5f, select, 0);
    case 4: return timed ? (InformationObject)SetpointCommandScaledWithCP56Time2a_create(NULL, 5004, 1234, select, 0, t)
                         : (InformationObject)SetpointCommandScaled_create(NULL, 5004, 1234, select, 0);
    case 5: return timed ? (InformationObject)SetpointCommandShortWithCP56Time2a_create(NULL, 5005, 21.5f, select, 0, t)
                         : (InformationObject)SetpointCommandShort_create(NULL, 5005, 21.5f, select, 0);
    default: return timed ? (InformationObject)Bitstring32CommandWithCP56Time2a_create(NULL, 5006, 0xA5A5A5A5u, t)
                          : (InformationObject)Bitstring32Command_create(NULL, 5006, 0xA5A5A5A5u);
    }
}

int
main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int port = 2404;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "-h")) host = argv[i + 1];
        else if (!strcmp(argv[i], "-p")) port = atoi(argv[i + 1]);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

#ifdef INTEROP_TLS
    TLSConfiguration tls = peer_tls("/pki/client.pem", "/pki/client.key");
    CS104_Connection con = CS104_Connection_createSecure(host, port, tls);
#else
    CS104_Connection con = CS104_Connection_create(host, port);
#endif
    CS104_Connection_setASDUReceivedHandler(con, asdu_handler, NULL);
    CS104_Connection_setConnectionHandler(con, connection_handler, NULL);
    if (!CS104_Connection_connect(con)) {
        puts("FAILED");
        return 1;
    }
    puts("CONNECTED");
    CS104_Connection_sendStartDT(con);
    for (int i = 0; i < 50 && !active; i++)
        Thread_sleep(100);
    if (!active) {
        puts("FAILED");
        return 1;
    }
    puts("ACTIVATED");
    settle();

    step("gi");
    CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
    settle();
#ifdef INTEROP_TLS
    await_completion(&gi_complete);
    step("command");
    command(con, (InformationObject)SingleCommand_create(NULL, 5000, true, false, 0));
    await_completion(&cmd_complete);
#else
    if (getenv("TEST_DIRECTORY")) {
        step("directory");
        FileCallOrSelect call = FileCallOrSelect_create(NULL, 0, 0, 0, 0);
        bool sent = CS104_Connection_sendProcessCommandEx(con, CS101_COT_REQUEST, 1, (InformationObject)call);
        FileCallOrSelect_destroy(call);
        if (!sent) return 2;
        for (int i = 0; i < 100 && !atomic_load(&directory_complete); ++i) Thread_sleep(50);
        if (!atomic_load(&directory_complete)) return 3;
        step("download");
        if (!file_message(con,(InformationObject)FileCallOrSelect_create(NULL,1,2,0,1)) || !await_stage(1) ||
            !file_message(con,(InformationObject)FileCallOrSelect_create(NULL,1,2,0,2)) || !await_stage(2) ||
            !file_message(con,(InformationObject)FileCallOrSelect_create(NULL,1,2,1,6)) || !await_stage(4) ||
            !file_message(con,(InformationObject)FileACK_create(NULL,1,2,1,3)) || !await_stage(5) ||
            !file_message(con,(InformationObject)FileACK_create(NULL,1,2,1,1))) return 4;
    }
    step("group");
    CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_GROUP_1);
    settle();
    step("counter");
    CS104_Connection_sendCounterInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QCC_RQT_GENERAL);
    settle();
    step("read");
    CS104_Connection_sendReadCommand(con, 1, 200);
    settle();

    struct sCP56Time2a now;
    CP56Time2a_createFromMsTimestamp(&now, Hal_getTimeInMs());
    step("clock");
    CS104_Connection_sendClockSyncCommand(con, 1, &now);
    settle();
    step("test");
    CS104_Connection_sendTestCommandWithTimestamp(con, 1, 0x4938, &now);
    settle();

    for (int timed = 0; timed < 2; timed++) {
        for (int kind = 0; kind < 7; kind++) {
            printf("STEP direct %d %d\n", kind, timed);
            command(con, make(kind, false, timed, &now));
        }
        for (int kind = 0; kind < 6; kind++) {
            printf("STEP select %d %d\n", kind, timed);
            command(con, make(kind, true, timed, &now));
            printf("STEP execute %d %d\n", kind, timed);
            command(con, make(kind, false, timed, &now));
        }
    }

    step("unknown-ioa");
    command(con, (InformationObject)SingleCommand_create(NULL, 6000, true, false, 0));
    step("unselected");
    command(con, (InformationObject)SingleCommand_create(NULL, 5100, true, false, 0));
    step("reset");
    {
        ResetProcessCommand rp = ResetProcessCommand_create(NULL, 0, IEC60870_QRP_GENERAL_RESET);
        CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, (InformationObject)rp);
        InformationObject_destroy((InformationObject)rp);
        settle();
    }
#endif
    step("end");
    CS104_Connection_destroy(con);
#ifdef INTEROP_TLS
    TLSConfiguration_destroy(tls);
#endif
    puts("EXIT");
    return 0;
}
