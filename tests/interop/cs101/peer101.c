/*
 * iec101-peer: lib60870-C as a configurable IEC 60870-5-101 peer for interop tests.
 *
 * Part of the iec60870 crate's test suite. Licensed MIT OR Apache-2.0, like the crate.
 * It links against lib60870-C (GPL-3), which the Dockerfile clones at a pinned commit.
 *
 * usage: iec101-peer master|slave balanced|unbalanced [options]
 *   --port PATH        serial port (default /tmp/ttyS)
 *   --addr N           unbalanced: the slave's link address; balanced: this end's address
 *   --other N          balanced: the other end's address
 *   --width N          link address octets (1 or 2; default 1)
 *   --send N           slave: queue N M_SP_NA_1 (IOA 100..) as class 1 and N M_ME_NB_1
 *                      (IOA 200..) as class 2; master: send N C_SC_NA_1 (IOA 300..)
 *   --duration MS      exit after MS milliseconds (default 10000)
 *
 * Application layer: the 101 profile (COT 1 octet, CA 1 octet, IOA 2 octets), CA 1.
 *
 * Prints one event per line on stdout:
 *   READY | LL <address> <IDLE|ERROR|BUSY|AVAILABLE> | ASDU <type> <ioa> <cot>
 *   SENT <n> | TX <hex> | RX <hex> | EXIT
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cs101_master.h"
#include "cs101_slave.h"
#include "hal_serial.h"
#include "hal_thread.h"
#include "hal_time.h"

static struct {
    bool master;
    bool balanced;
    const char* port;
    int addr, other, width, send, duration;
} opt = {false, false, "/tmp/ttyS", 1, 2, 1, 0, 10000};

static volatile bool available = false;

static void
raw(void* parameter, uint8_t* msg, int size, bool sent)
{
    (void) parameter;
    printf("%s ", sent ? "TX" : "RX");
    for (int i = 0; i < size; i++)
        printf("%02x", msg[i]);
    printf("\n");
    fflush(stdout);
}

static void
state(void* parameter, int address, LinkLayerState s)
{
    (void) parameter;
    const char* name = s == LL_STATE_IDLE ? "IDLE" : s == LL_STATE_ERROR ? "ERROR" : s == LL_STATE_BUSY ? "BUSY" : "AVAILABLE";
    available = s == LL_STATE_AVAILABLE;
    printf("LL %d %s\n", address, name);
    fflush(stdout);
}

static void
print_asdu(CS101_ASDU asdu)
{
    int ioa = -1;
    InformationObject io = CS101_ASDU_getElement(asdu, 0);
    if (io) {
        ioa = InformationObject_getObjectAddress(io);
        InformationObject_destroy(io);
    }
    printf("ASDU %d %d %d\n", CS101_ASDU_getTypeID(asdu), ioa, CS101_ASDU_getCOT(asdu));
    fflush(stdout);
}

static bool
master_asdu(void* parameter, int address, CS101_ASDU asdu)
{
    (void) parameter;
    (void) address;
    print_asdu(asdu);
    return true;
}

static bool
slave_asdu(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    (void) parameter;
    (void) connection;
    print_asdu(asdu);
    return true;
}

static void
profile(CS101_AppLayerParameters al)
{
    al->sizeOfCOT = 1;
    al->sizeOfCA = 1;
    al->sizeOfIOA = 2;
    al->maxSizeOfASDU = 253;
}

static int
run_master(SerialPort port)
{
    CS101_Master master = CS101_Master_create(port, NULL, NULL, opt.balanced ? IEC60870_LINK_LAYER_BALANCED : IEC60870_LINK_LAYER_UNBALANCED);
    CS101_Master_getLinkLayerParameters(master)->addressLength = opt.width;
    profile(CS101_Master_getAppLayerParameters(master));
    CS101_Master_setASDUReceivedHandler(master, master_asdu, NULL);
    CS101_Master_setLinkLayerStateChanged(master, state, NULL);
    CS101_Master_setRawMessageHandler(master, raw, NULL);
    if (opt.balanced) {
        CS101_Master_setOwnAddress(master, opt.addr);
        CS101_Master_useSlaveAddress(master, opt.other);
    }
    else {
        CS101_Master_addSlave(master, opt.addr);
        CS101_Master_useSlaveAddress(master, opt.addr);
    }
    printf("READY\n");
    fflush(stdout);
    uint64_t end = Hal_getMonotonicTimeInMs() + opt.duration;
    uint64_t next_poll = 0;
    int sent = 0;
    while (Hal_getMonotonicTimeInMs() < end) {
        uint64_t now = Hal_getMonotonicTimeInMs();
        if (!opt.balanced && now >= next_poll && CS101_Master_isChannelReady(master, opt.addr)) {
            CS101_Master_pollSingleSlave(master, opt.addr);
            next_poll = now + 50;
        }
        bool ready = opt.balanced ? available : CS101_Master_isChannelReady(master, opt.addr);
        if (sent < opt.send && available && ready) {
            InformationObject sc = (InformationObject) SingleCommand_create(NULL, 300 + sent, true, false, 0);
            CS101_Master_sendProcessCommand(master, CS101_COT_ACTIVATION, 1, sc);
            InformationObject_destroy(sc);
            sent++;
            printf("SENT %d\n", sent);
            fflush(stdout);
        }
        CS101_Master_run(master);
        Thread_sleep(1);
    }
    CS101_Master_destroy(master);
    return 0;
}

static int
run_slave(SerialPort port)
{
    CS101_Slave slave = CS101_Slave_create(port, NULL, NULL, opt.balanced ? IEC60870_LINK_LAYER_BALANCED : IEC60870_LINK_LAYER_UNBALANCED);
    CS101_Slave_getLinkLayerParameters(slave)->addressLength = opt.width;
    CS101_AppLayerParameters al = CS101_Slave_getAppLayerParameters(slave);
    profile(al);
    CS101_Slave_setLinkLayerAddress(slave, opt.addr);
    if (opt.balanced)
        CS101_Slave_setLinkLayerAddressOtherStation(slave, opt.other);
    CS101_Slave_setASDUHandler(slave, slave_asdu, NULL);
    CS101_Slave_setLinkLayerStateChanged(slave, state, NULL);
    CS101_Slave_setRawMessageHandler(slave, raw, NULL);
    for (int i = 0; i < opt.send; i++) {
        CS101_ASDU a = CS101_ASDU_create(al, false, CS101_COT_SPONTANEOUS, 0, 1, false, false);
        InformationObject io = (InformationObject) SinglePointInformation_create(NULL, 100 + i, i % 2 == 0, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        CS101_Slave_enqueueUserDataClass1(slave, a);
        CS101_ASDU_destroy(a);
        a = CS101_ASDU_create(al, false, CS101_COT_PERIODIC, 0, 1, false, false);
        io = (InformationObject) MeasuredValueScaled_create(NULL, 200 + i, 1000 + i, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        CS101_Slave_enqueueUserDataClass2(slave, a);
        CS101_ASDU_destroy(a);
    }
    printf("READY\n");
    fflush(stdout);
    uint64_t end = Hal_getMonotonicTimeInMs() + opt.duration;
    while (Hal_getMonotonicTimeInMs() < end) {
        CS101_Slave_run(slave);
        Thread_sleep(1);
    }
    CS101_Slave_destroy(slave);
    return 0;
}

int
main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: iec101-peer master|slave balanced|unbalanced [options]\n");
        return 2;
    }
    opt.master = strcmp(argv[1], "master") == 0;
    opt.balanced = strcmp(argv[2], "balanced") == 0;
    for (int i = 3; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--port")) opt.port = argv[i + 1];
        else if (!strcmp(argv[i], "--addr")) opt.addr = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--other")) opt.other = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--width")) opt.width = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--send")) opt.send = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--duration")) opt.duration = atoi(argv[i + 1]);
    }
    SerialPort port = SerialPort_create(opt.port, 9600, 8, 'E', 1);
    if (!SerialPort_open(port)) {
        printf("FAILED open %s\n", opt.port);
        return 1;
    }
    int rc = opt.master ? run_master(port) : run_slave(port);
    SerialPort_close(port);
    SerialPort_destroy(port);
    printf("EXIT\n");
    fflush(stdout);
    return rc;
}
