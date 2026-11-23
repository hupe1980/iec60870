/*
 * iec104-peer: lib60870-C as a configurable IEC 60870-5-104 peer for interop tests.
 *
 * Part of the iec60870 crate's test suite. Licensed MIT OR Apache-2.0, like the crate.
 * It links against lib60870-C (GPL-3), which the Dockerfile clones at a pinned commit.
 *
 * usage: iec104-peer server|client [options]
 *   -h HOST            client: host to connect to (default 127.0.0.1)
 *   -p PORT            port (default 2404)
 *   -k N -w N          APCI windows
 *   --t0 S --t1 S --t2 S --t3 S   APCI timers in seconds
 *   --start            client: send STARTDT act once connected
 *   --send N           send N ASDUs once data transfer is active (server: M_SP_NA_1
 *                      spontaneous, IOA 0..N-1; client: C_SC_NA_1 activation, IOA 0..N-1),
 *                      waiting while the transmit window is full
 *   --stop-after MS    client: send STOPDT act MS milliseconds after STARTDT con
 *   --duration MS      exit after MS milliseconds (default 10000)
 *
 * Prints one event per line on stdout:
 *   READY | CONNECTED | STARTDT_CON | STOPDT_CON | ACTIVATED | DEACTIVATED | CLOSED | FAILED
 *   ASDU <type> <ioa>  | SENT <n> | FULL | TX <hex frame> | RX <hex frame> | EXIT
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cs104_connection.h"
#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"

static struct {
    bool server;
    const char* host;
    int port;
    int k, w, t0, t1, t2, t3;
    bool start;
    int send;
    int stop_after;
    int duration;
} opt = {false, "127.0.0.1", 2404, -1, -1, -1, -1, -1, -1, false, 0, -1, 10000};

static volatile bool active = false;
static volatile bool closed = false;

static void
print_frame(const char* dir, uint8_t* msg, int size)
{
    char line[1024];
    int pos = snprintf(line, sizeof(line), "%s", dir);
    for (int i = 0; i < size && pos < (int)sizeof(line) - 4; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, " %02x", msg[i]);
    puts(line);
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
    printf("ASDU %d %d\n", (int)CS101_ASDU_getTypeID(asdu), ioa);
}

static void
apply_apci(CS104_APCIParameters p)
{
    if (opt.k >= 0) p->k = opt.k;
    if (opt.w >= 0) p->w = opt.w;
    if (opt.t0 >= 0) p->t0 = opt.t0;
    if (opt.t1 >= 0) p->t1 = opt.t1;
    if (opt.t2 >= 0) p->t2 = opt.t2;
    if (opt.t3 >= 0) p->t3 = opt.t3;
}

/* ---- server ---------------------------------------------------------------------------- */

static void
server_raw(void* param, IMasterConnection con, uint8_t* msg, int size, bool sent)
{
    (void)param; (void)con;
    print_frame(sent ? "TX" : "RX", msg, size);
}

static bool
server_asdu(void* param, IMasterConnection con, CS101_ASDU asdu)
{
    (void)param; (void)con;
    print_asdu(asdu);
    return true;
}

static void
server_event(void* param, IMasterConnection con, CS104_PeerConnectionEvent event)
{
    (void)param; (void)con;
    switch (event) {
    case CS104_CON_EVENT_CONNECTION_OPENED: puts("CONNECTED"); break;
    case CS104_CON_EVENT_CONNECTION_CLOSED: puts("CLOSED"); closed = true; active = false; break;
    case CS104_CON_EVENT_ACTIVATED: puts("ACTIVATED"); active = true; break;
    case CS104_CON_EVENT_DEACTIVATED: puts("DEACTIVATED"); active = false; break;
    }
}

static int
run_server(void)
{
    CS104_Slave slave = CS104_Slave_create(100, 100);
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, opt.port);
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
    apply_apci(CS104_Slave_getConnectionParameters(slave));
    CS104_Slave_setASDUHandler(slave, server_asdu, NULL);
    CS104_Slave_setConnectionEventHandler(slave, server_event, NULL);
    CS104_Slave_setRawMessageHandler(slave, server_raw, NULL);
    CS104_Slave_start(slave);
    if (!CS104_Slave_isRunning(slave)) {
        puts("FAILED");
        return 1;
    }
    puts("READY");

    CS101_AppLayerParameters al = CS104_Slave_getAppLayerParameters(slave);
    uint64_t end = Hal_getTimeInMs() + opt.duration;
    int sent = 0;
    while (Hal_getTimeInMs() < end) {
        if (active && sent < opt.send) {
            CS101_ASDU asdu = CS101_ASDU_create(al, false, CS101_COT_SPONTANEOUS, 0, 1, false, false);
            InformationObject io = (InformationObject)SinglePointInformation_create(NULL, sent, true, IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(asdu, io);
            InformationObject_destroy(io);
            CS104_Slave_enqueueASDU(slave, asdu);
            CS101_ASDU_destroy(asdu);
            sent++;
            printf("SENT %d\n", sent);
        }
        Thread_sleep(5);
    }
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    puts("EXIT");
    return 0;
}

/* ---- client ---------------------------------------------------------------------------- */

static volatile bool startdt_con = false;
static uint64_t startdt_con_at = 0;

static void
client_raw(void* param, uint8_t* msg, int size, bool sent)
{
    (void)param;
    print_frame(sent ? "TX" : "RX", msg, size);
}

static bool
client_asdu(void* param, int address, CS101_ASDU asdu)
{
    (void)param; (void)address;
    print_asdu(asdu);
    return true;
}

static void
client_event(void* param, CS104_Connection con, CS104_ConnectionEvent event)
{
    (void)param; (void)con;
    switch (event) {
    case CS104_CONNECTION_OPENED: puts("CONNECTED"); break;
    case CS104_CONNECTION_CLOSED: puts("CLOSED"); closed = true; break;
    case CS104_CONNECTION_FAILED: puts("FAILED"); closed = true; break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        puts("STARTDT_CON");
        startdt_con_at = Hal_getTimeInMs();
        startdt_con = true;
        break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED: puts("STOPDT_CON"); break;
    }
}

static int
run_client(void)
{
    CS104_Connection con = CS104_Connection_create(opt.host, opt.port);
    apply_apci(CS104_Connection_getAPCIParameters(con));
    CS104_Connection_setConnectionHandler(con, client_event, NULL);
    CS104_Connection_setASDUReceivedHandler(con, client_asdu, NULL);
    CS104_Connection_setRawMessageHandler(con, client_raw, NULL);

    uint64_t end = Hal_getTimeInMs() + opt.duration;
    bool connected = false;
    while (!connected && Hal_getTimeInMs() < end) {
        connected = CS104_Connection_connect(con);
        if (!connected)
            Thread_sleep(100);
    }
    if (!connected) {
        puts("FAILED");
        CS104_Connection_destroy(con);
        return 1;
    }
    if (opt.start)
        CS104_Connection_sendStartDT(con);

    int sent = 0;
    bool full_reported = false;
    bool stopped = false;
    while (Hal_getTimeInMs() < end && !closed) {
        if (startdt_con && sent < opt.send) {
            if (CS104_Connection_isTransmitBufferFull(con)) {
                if (!full_reported) {
                    puts("FULL");
                    full_reported = true;
                }
            }
            else {
                InformationObject sc = (InformationObject)SingleCommand_create(NULL, sent, true, false, 0);
                if (CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, sc)) {
                    sent++;
                    printf("SENT %d\n", sent);
                }
                InformationObject_destroy(sc);
            }
        }
        if (startdt_con && !stopped && opt.stop_after >= 0 && Hal_getTimeInMs() >= startdt_con_at + (uint64_t)opt.stop_after) {
            CS104_Connection_sendStopDT(con);
            stopped = true;
        }
        Thread_sleep(5);
    }
    CS104_Connection_destroy(con);
    puts("EXIT");
    return 0;
}

int
main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2 || (strcmp(argv[1], "server") != 0 && strcmp(argv[1], "client") != 0)) {
        fprintf(stderr, "usage: iec104-peer server|client [options]\n");
        return 2;
    }
    opt.server = strcmp(argv[1], "server") == 0;
    for (int i = 2; i < argc; i++) {
        const char* a = argv[i];
        const char* v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(a, "--start") == 0) { opt.start = true; continue; }
        if (v == NULL) { fprintf(stderr, "missing value for %s\n", a); return 2; }
        i++;
        if (strcmp(a, "-h") == 0) opt.host = v;
        else if (strcmp(a, "-p") == 0) opt.port = atoi(v);
        else if (strcmp(a, "-k") == 0) opt.k = atoi(v);
        else if (strcmp(a, "-w") == 0) opt.w = atoi(v);
        else if (strcmp(a, "--t0") == 0) opt.t0 = atoi(v);
        else if (strcmp(a, "--t1") == 0) opt.t1 = atoi(v);
        else if (strcmp(a, "--t2") == 0) opt.t2 = atoi(v);
        else if (strcmp(a, "--t3") == 0) opt.t3 = atoi(v);
        else if (strcmp(a, "--send") == 0) opt.send = atoi(v);
        else if (strcmp(a, "--stop-after") == 0) opt.stop_after = atoi(v);
        else if (strcmp(a, "--duration") == 0) opt.duration = atoi(v);
        else { fprintf(stderr, "unknown option %s\n", a); return 2; }
    }
    return opt.server ? run_server() : run_client();
}
