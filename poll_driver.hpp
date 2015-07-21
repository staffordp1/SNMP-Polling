#ifndef DRIVER_H
#define DRIVER_H

#include "fmt.hpp"
#include "snmpRec.hpp"
#include "pqDB.hpp"
#include "orDB.hpp"
#include "../include/NAC_conf.hpp"
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>


#define LOCK_FILE_DIR "/home/nacmgr/var/"
#define ARP_SCRIPT "/home/nacmgr/bin/scripts/getARP.bsh"
#define FW_SCRIPT "/home/nacmgr/bin/scripts/fw_arp.bsh"
#define INSIDE_FW_SCRIPT "/home/nacmgr/bin/scripts/fw_inside_arp.bsh"
#define OUTSIDE_FW_SCRIPT "/home/nacmgr/bin/scripts/fw_outside_arp.bsh"
#define BRIDGE_SCRIPT "/home/nacmgr/bin/expect_lib/get_bridge.bsh"
#define MEC_ARP "/home/nacmgr/bin/scripts/mec_arp.bsh"

extern uint NAC_THREADS;

typedef hash_map<string, string *, stringhasher> walkRecord_t;
typedef hash_map<string, polling_record *, stringhasher> pList_t;
typedef hash_map<string, arp_record_t *, stringhasher> aList_t;
typedef map<string, int> map_t;

class L3_record {  // used in main() only
public:
  sys_t L3sys;
  list<sys_t *> *L2_list;
};

extern pqDB *pq;
extern bool DEBUG, SILENT, DO_SCAN;
extern string DB_HOST;
extern snmpRec *s;

// poll_driver.cpp
void remove_lock();
bool lock_application();
void log_record(string dev, string mac, string owner, string status, string notes);
void print_sys_record(sys_t *S);
void print_arp_record(arp_record_t A);
void *get_arp_data(void *arecord);
void *get_bridge_data(void *arecord);
bool update_L3_polling(list<sys_t *> L2, sys_t *L3sys);
void parse_options(int argc, char *argv[]);
void check_L2_ports(list<L3_record *> *L3_list);


// poll_history.cpp
string get_L2_id (string vlan, string L3, string ip);
bool add_to_polling(polling_record *pR);
bool get_polling_record(string the_mac, polling_record *pR);
bool update_polling_time(string mac);
bool update_history_time(uint id, string dt);
bool defined_in_history(string mac);
bool get_last_history(string mac, polling_record *pR);
bool insert_history(polling_record *p);
bool archive_polling(polling_record *p);
bool delete_from_polling(string mac);
void add_to_scan_queue(string mac, string ip, string last_dt);
void update_polling(vector<polling_record *> *P);
void get_NO_SNMP_BRIDGE(sys_t *);


#endif
