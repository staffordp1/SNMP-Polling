
#include "poll_driver.hpp"
#include <iostream>
#include <fstream>

#include <pwd.h>

fmt f;

typedef hash_map<string, polling_record *, stringhasher> pList_t;
typedef hash_map<string, arp_record_t *, stringhasher> aList_t;
typedef hash_map<string, string *, stringhasher> walkRecord_t;
typedef map<string, int> map_t;
typedef walkRecord_t::iterator iter_h_t;
typedef hash_map<string, polling_record *, stringhasher> pHash_t;

int TTL;

typedef struct {
  list<sys_t *> *L2_list;
  sys_t *S;
} dbl_sys_t;


string L2_IP_ADDR, ROUTER, OUTPOST, DB_HOST, LOCK_FILE;
string taskID;

// global snmp handle

snmpRec *s;
pqDB *pq;

bool DEBUG, SILENT, DO_SCAN, FORCE;
uint NAC_THREADS;

void myComment(string myS)
{
  if(!DEBUG) return;
  cout << myS << " (Debug)\n";  fflush(stdout);
}

void remove_lock() 
{
  unlink(LOCK_FILE.c_str()); 
}

bool open_NAC_db()
{
  if(pq==0) pq = new pqDB();
  if(pq->pq_open()) return true;

  if(!SILENT) cout << "Failed to open NAC database\n";
  sleep(15);
  if(pq->pq_open()) return true;
  return false;
}

void clean_up()
{
  if(pq != 0) { delete pq; pq=0; }
  if(s != 0) { delete s; s=0; }
}

//-------------------------------------------------------------------------------
bool on_task(string task)
{

  string myBuf ("select count(*) from monitor where task='" + task  +
                "' and (date_last_executed is null "
                "or cast(current_timestamp - date_last_executed as interval) > delta_t)");

  if(pq->pq_count(myBuf) == 0) {
      myComment(task + ": not on task (not time for execution)");
      return false;
  }
  return true;
}


//--------------------------------------------------------------------
void send_error(string msg)
{
  if(msg.length()==0) return;

  log_record("error", msg, "", "", "");
  return;

  /*-- Make a unique filename for your temp file using mktemp() */
  char *tempfile=(char *)malloc(64);
  int fd;

  strcpy(tempfile,"/tmp/NACmonitor-mail.XXXXXX");
  fd = mkstemp(tempfile);
  if (fd<0) {
      perror("SendMail: fopen");
      return;
  }

  /*-- Write to the tempfile and then close it */
  uint len = 128+msg.length()+ (msg.length()%8);
  char myBuf[len];
  sprintf(myBuf, "To:pst@ornl.gov\nCc:azr@ornl.gov\nFrom: NACmonitor@%s.ornl.gov\n"
                 "Subject: NACmgr POLLING error\n\n%s\n", LOCAL_HOST, msg.c_str());
  len = strlen(myBuf);

  // ssize_t write(int fildes, const void *buf, size_t nbyte);
  size_t ret_val = write(fd, (const void *) myBuf, len);
  if( ret_val < len) {
      perror("ERROR: write to fd");
      return;
  }

  close(fd);
  string myS ("/usr/lib/sendmail -t < ");
  myS += tempfile;
  if(system(myS.c_str()) !=0) perror("ERROR SendMail: system call");
  unlink(tempfile);
}


/*-------------------------------------------------------------------*/
void NACalarmHandler(int alarm_type)
{
  //-- Write to the tempfile and then close it
  char myBuf[512];
  sprintf(myBuf, "To:pst@ornl.gov\nFrom: %s@%s.ornl.gov\n"
                 "Subject: NACd error\n\nNAC alarmHander: ", OUTPOST.c_str(), LOCAL_HOST);

  if(alarm_type==SIGALRM) {
      strcat(myBuf, "exceeded TTL time in execution: TIMED OUT\n");
  }
  else strcat(myBuf, strerror(errno));

  if(!SILENT) cout << myBuf << endl;

  remove_lock();
  exit(1);
}


bool lock_application()
{
  FILE *lockfile;

  struct stat file_stat;

  LOCK_FILE = LOCK_FILE_DIR + OUTPOST + ".lock";

  if( stat(LOCK_FILE.c_str(), &file_stat) == 0) {
    cerr << "Unable to lock NACmgmt polling (" << LOCK_FILE << "): Another application running?\n";
    return false;
  }

  lockfile = fopen(LOCK_FILE.c_str(), "w+");

  if(lockfile != NULL) {
    fprintf(lockfile, "%d", getpid());
    fclose(lockfile);
    atexit(remove_lock);

  } else {
    cerr << "Unable to create lockfile: " << LOCK_FILE << endl;
    return false;
  }
  myComment("Successfully created lockfile: " + LOCK_FILE);

  signal(SIGALRM, NACalarmHandler);
  alarm(TTL);
  return true;
}


//-------------------------------------------------------------------------------
void log_record(string dev, string mac, string owner, string status, string notes)
{
  string myDate = pq->get_current_date();

  FILE *F;

  cout << "LOG: " << dev << "\t" << mac << "\t" << owner << "\t" << status << "\t" << notes << "\n";
  return;

  F=fopen(LOG, "ab+");
  if(F == NULL) { printf("Cannot open output file %s\n", LOG); exit(1); }

  uint loc = notes.find("|");
  while(loc != string::npos) {
      notes.replace(loc, 1, " -- ");
      loc = notes.find("|");
  }
  fprintf(F,"%s|", myDate.c_str());
  fprintf(F,"NACmgr|");
  fprintf(F,"%s|", status.c_str());
  fprintf(F,"%s|", dev.c_str());
  fprintf(F,"%s|", mac.c_str());
  fprintf(F,"%s|", owner.c_str());
  fprintf(F,"%s\n", notes.c_str());
  fclose(F);
}
 
//---------------------------------------------------------------------------------
void print_sys_record(sys_t *S)
{
  if(SILENT) return;

  cout << S->ip << "\t";
  cout << S->sysType << "\t";
  cout << S->L3 << "\t";
  cout << S->comm ;

  if(S->IgnorePorts.size() > 0) {
      cout << endl;
      for(map_t::iterator i= S->IgnorePorts.begin(); i!= S->IgnorePorts.end(); ++i)
          cout << "\t\tIgnore_Port: " << i->first << endl;
  }
  cout << endl;
}

void print_arp_record(arp_record_t A)
{
  if(SILENT) return;
  cout << A.ip << "\t" << A.mac << " \t" << "vlan: " << A.vlan << endl;
}

unsigned int system_ssh_only(int sysType)
{
  char myBuf[256];
  if( !(sysType > 0) ) return 0;

  sprintf(myBuf, "select count(*) from systypes where id=%d and protocol='SSH'", sysType);
  myComment(myBuf);
  if(pq->pq_count(myBuf) > 0) return 1;
  return 0;
}


unsigned int is_ARP_only(int  sysType)
{
  //char myBuf[256];
  //sprintf(myBuf, "select count(*) from systypes where id=%d and ssh='Y'", sysType);
  //if(pq->pq_count(myBuf) > 0) return 1;

  if(sysType== _INSIDE_FW_
     || sysType== _OUTSIDE_FW_
     || sysType== _FW_
     || sysType== _VRF_
     || sysType== _CASA5520_FW_ )
  {
      cerr << sysType << ": Is SSH ONLY\n";
      return 1;
  }
  return 0;
}


//-----------------------------------------------------------------------------
//populates rec->A with ARP data.
//-----------------------------------------------------------------------------
bool getARPcache(sys_t *rec)
{
  myComment("getARPcache(" + rec->L3 + ", " + rec->ip + ")\n");

  if(!rec->vlan.length() ) {
      string myBuf("select max(v.vlan) from vlans v, l2_networks n where upper(v.l3_name)=upper('"+rec->L3+"') and "
                   "inet(n.l2_ip_addr)= inet('" + rec->ip + "') and v.vlan_id=n.vlan_id and vlan!='local' and status!='OFF-LINE' "
                   "group by v.L3_name");
      myComment(myBuf);
      rec->vlan=pq->pq_string(myBuf);
  }
  if(!rec->vlans.size()) {
      string myBuf("select v.vlan from vlans v, l2_networks n where upper(v.l3_name)=upper('"+rec->L3+"') and "
                   "inet(n.l2_ip_addr)= inet('" + rec->ip + "') and v.vlan_id=n.vlan_id and v.vlan!='local' and v.status!='OFF-LINE'");
      myComment(myBuf);
      rec->vlans=pq->pq_list(myBuf.c_str());
  }
  cerr  << "L3 Vlan: " << rec->vlan << "\n";

  // first make the tmp file
  char *tempfile=(char *)malloc(64);
  sprintf(tempfile, "/tmp/getARPcache%s.XXXXXX", rec->ip.c_str());

  if(mkstemp(tempfile)<0) {
      perror("getARPcache(mkstemp) system call error"); fflush(stderr);
      unlink(tempfile);
      return false;
  }
  string comm = pq->pq_string("select n.view_pwd||' '||n.enable_pwd||' '||n.user_id from networks n, L3_routers l "
                              "where l.l3_name='" + rec->L3 + "' and l.network_id=n.network_id");
  string ip = f.fmt_ip_for_network(rec->ip);

  string myCommand;

  // ALL of these scripts returns tuples of [ip, mac, vlan] 

  // type4 firewalls == _FW_ 
  if(rec->sysType== _OUTSIDE_FW_ || rec->sysType== _FW_W_SWITCHES_ || rec->sysType== _FW_ ) {
      cerr << "systype in [_FW_, _OUTSIDE_FW_ | _FW_W_SWITCHES_]\n";
      myCommand = (string(ARP_SCRIPT) + " " + ip.c_str() + " " + comm + " " + rec->vlan + " -o > " + tempfile);
  }
  else if(rec->sysType== _VRF_ ) {
  //USAGE: ./getArp.bsh [sw_ip] [view pwd] [enable pwd] [UserID (defaults to 'view')] [option]"
      cerr << "systype = _VRF_\n"; 
      myCommand = (string(ARP_SCRIPT) + " " + ip.c_str() + " " + comm + " -v > " + tempfile);
  }
  else if(rec->sysType== _INSIDE_FW_ || rec->sysType== _CASA5520_FW_ ) {
      cerr << "systype = _INSIDE_FW\n"; 
      myCommand = (string(ARP_SCRIPT) + " " + ip.c_str() + " " + comm + " " + rec->vlan + " -i > " + tempfile);
  }
  else {
      cerr << "systype = DEFAULT(" << rec->sysType << ")\n"; 
      myCommand = (string(ARP_SCRIPT) + " " + ip.c_str() + " " + comm + " > " + tempfile);
  }

  cerr << myCommand << "\n";
  errno=0;

  if(system(myCommand.c_str()) != 0) {
      cout << myCommand << endl; fflush(stderr);
      perror("getARPcache:: system call error");
      unlink(tempfile); // remove the file from /tmp
      return false;
  }

  myComment(myCommand);

  // Open output file for retrieving data [ip, mac] tuples
  ifstream in_file(tempfile, ios::in);
  if(!in_file) {
      unlink(tempfile); // remove the file from /tmp
      send_error("getARPcache:: Unable to open input stream -- filename: '" + string(tempfile) + "'");
      return false;
  }

  //process file contents
  //
  char line[1024];

  while ( ! in_file.eof() )
  {
      bzero(line, 1024);
      in_file.getline (line, 1024);
      string myS = f.fmt_lower(line); // process the line into IP, MAC
      if(DEBUG) cout << line << "\n";

      myS = f.trim(myS);
      if(myS.length()==0) continue;

      list_t words = f.split(myS, ' ');
      list_t::iterator w=words.begin();

      if(words.size()!=3) {
          if(DEBUG) cout << "BAD Format -- word size (" << words.size() << " < 3 (" << line << ", myS='" << myS << "') -- next line\n";
          continue;
      }
      if(DEBUG) cout << "(OK) Line: " << line << "\n";

      //e.g. : 128.219.253.2 0050.455b.a5c8 2
      string ip = f.fmt_ip(*w); w++;
      string mac = f.fmt_mac(*w); w++;
      string vlan = *w;
      if(DEBUG) cout << "IP: " << ip << " MAC: " << mac << " vlan: " << vlan << "\n";

      if( rec->vlans[vlan]!=1 ) {
          if(DEBUG) cout << "VLAN " << vlan << " is not in list--aborting this record\n"; 
          continue;
      }
      if(DEBUG) cout << "-- vlan found--\n";

      int myVlan = atoi ( (char *)vlan.c_str());
      arp_record_t *aR;

      // see if the mac has more than one IP
      hash_map<string, arp_record_t *, stringhasher>::iterator aiter = rec->A.find( mac );

      if(aiter == rec->A.end()) 
      {
          if(DEBUG) cout << "Found new mac in ARP (" << mac << ")\n";
          // first occurrence of mac address
          aR = new arp_record_t();
          aR->mac=mac;
          aR->ip=ip;
          aR->vlan=vlan;
          aR->ips.insert (make_pair(aR->ip, myVlan));
          rec->A.insert( make_pair(aR->mac, aR) );
      }
      else {
          // mac has more than one IP address
          if(DEBUG) cout << "Found mac in ARP list (" << mac << ")\n";
          aR = aiter->second;
          aR->ips.insert (make_pair(aR->ip, myVlan));
      }
   }

  unlink(tempfile); // remove the file from /tmp
  if(!rec->A.size()) {
       if(DEBUG) cout << "\n--------\n\tgetARP(" << rec->L3 << ") :: No records found\n";
       return false;
  }
  return true;
}


//----------------------------------------------------------
// After defing VLANS to be polled, retrieves the ARP data
void retrieveARP_using_ssh(sys_t *rec)
{
  // ssh protocol
  if(!getARPcache(rec)) {
      cerr << "Failed to get ARP for L3 " << rec->L3 << "\n";
  }
  if(!DEBUG) return;
  
  if(rec->A.size()==0) send_error("Failed to get ARP for L3 " + rec->L3);
  else if (DEBUG) {
      cout << "ARP LIST: \n";
      int num=1;
      for(hash_map<string, arp_record_t *, stringhasher>::iterator a = rec->A.begin(); a!=rec->A.end(); a++)
      {
          arp_record_t *aRec = a->second;
          cout <<  "\t(" << num++ << "): " << aRec->mac << "\t" << aRec->ip << "\t" << aRec->vlan << "\n";
      }
  }
}

// Retrieve ARP data from router (L3), either by ssh or SNMP.  
// If SNMP should fail, resort to ssh.
//-------------------------------------------------------------------
void *get_arp_data(void *arecord)
{
  sys_t *rec = (sys_t *)arecord;

  if(DEBUG) cout << "get_arp_data()::\n\tL3 == " << rec->L3 << "\tL3 systype == " << rec->sysType << "\n";
  fflush(stdout);

  // do ssh session
  if(system_ssh_only(rec->sysType)==1) {
      if(DEBUG) cout << "USING SSH to retrieve ARP:\n"; fflush(stdout);
      retrieveARP_using_ssh(rec);
  }
  else {
      // else do SNMP session
      if(DEBUG) cout << "USING SNMP to retrieve ARP:\n"; fflush(stdout);
      s->get_arp( rec );
      if( (!rec->A.size()) && (rec->sysType !=_CISCO_NO_SSH_) ) {
          if(DEBUG) cout << "RESULTS: have to use SSH since SNMP failed\n";
          retrieveARP_using_ssh(rec);
      }
  }
/*
  if(DEBUG) {
      cout << "RESULTS\nget_arp_data results:\n";
      for(hash_map<string, arp_record_t *, stringhasher>::iterator iter=rec->A.begin(); iter!=rec->A.end(); iter++)
      {
          arp_record_t *aRec=iter->second;
          if(!aRec->vlan.length()) {
              cerr << "Unable to get VLAN for this ARP data to update polling: " << aRec->mac << " L3: " << aRec->ip << "\n";
              // discard record....
          }
          else cout << aRec->mac << "\tVlan: "<<aRec->vlan;

          for(map_t::iterator m=aRec->ips.begin(); m != aRec->ips.end(); m++) {
              if( m!=aRec->ips.begin()) cout << ",";
              cout << m->first;
          }
          cout << "\t(L3): " << aRec->ip << "\n";
      }
  }
*/
  return arecord;
}

//-------------------------------------------
void *get_bridge_data(void *arecord)
{
  sys_t *rec = (sys_t *)arecord;

  myComment("get_bridge_data("+ rec->ip +")");

  if(system_ssh_only(rec->sysType)) {
      myComment("get_bridge_data( "+ rec->ip +") -- get_NO_SNMP_BRIDGE() ==0"); fflush(stdout);
      get_NO_SNMP_BRIDGE(rec);
      return 0;
  }
  fflush(stdout);

  if(DEBUG) cout << "get_bridge_data(" << rec->ip << ", "<< rec->vlan << " (systype=" << rec->sysType << "))\n";


  walkRecord_t *h0 = new walkRecord_t();
  walkRecord_t *portMapping = new walkRecord_t();

  if(!s->get_IF_indexes(rec, h0)) {
      myComment("Failed to get vlans for L2: " + rec->ip);
      return arecord;
  }

  if(DEBUG) {
      string myS("\nVLANS defined for " + rec->ip + " are: ");
      for(map_t::iterator m_iter = rec->vlans.begin(); m_iter != rec->vlans.end(); m_iter++) {
          if(m_iter != rec->vlans.begin()) myS += ", ";
          myS += m_iter->first;
      }
      myS+="\n";
      fflush(stdout);
      cout << myS; fflush(stdout);
  }

  // for each Vlan
  for( map_t::iterator m_iter = rec->vlans.begin(); m_iter != rec->vlans.end(); m_iter++)
  {
      string vlan = m_iter->first;
      if(vlan.length() > 0) {
          vlan_P_rec *vP = new vlan_P_rec();
          vP->rec = rec;
          vP->h0 = h0;
          vP -> portMapping = portMapping;
          vP->vlan = vlan;
          s->get_vlan_polling_data(vP);
       }
  }
  rec->d2 = pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  return arecord;
}


//----------------------------------------------------------------------------
void update_L2_poll_time(string ip, string dt1, string dt2)
{
  if (!dt2.length()) {
      dt2=pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  }
  if(!dt1.length()) dt1=s->current_timestamp;

  string myIP= f.fmt_ip(ip);
  string myBuf("update L2_switches set poll_start_time=timestamp '" + dt1 + "', poll_end_time=timestamp '" + dt2 
		+ "' where L2_ip_addr = '" + myIP + "'");
  if(!pq->pq_exec (myBuf)) {
      if(!SILENT) cout << "Error updating  L2_switches poll_end_time: " << myBuf << "\n";
  }
}


//----------------------------------------------------------------------------------------
void send_pthread_error(uint num)
{
  char myperror[256];

  sprintf(myperror, "\n%s\n", strerror(errno));
  string errorBuf;

  if(num == EAGAIN) {
      errorBuf = "The system lacked the necessary resources to create another thread, "
                 "or the system-imposed limit on the total number of threads in a "
                 "process [PTHREAD_THREADS_MAX] would be exceeded.";
  }
  else if(num==EINVAL) errorBuf = "The value specified by attr is invalid";
  else if(num==EPERM) {
      errorBuf = "The caller does not have appropriate permission to set "
                 "the required scheduling parameters or scheduling policy";
  }
  else {
          char myBuf[128]; sprintf(myBuf, "Unknown error code: %d\n", num);
          errorBuf = string(myBuf);
  }
  send_error("Unable to create thread: " + errorBuf + string(myperror));
  if(DEBUG) cout <<"exiting deut to pthread_error(" << num << ")\n" << errorBuf << "\n";
}


// this is a switch if we're looking at bridge data.
//----------------------------------------------------------------------
void get_NO_SNMP_BRIDGE(sys_t *rec)
{
  myComment("get_NO_SNMP_BRIDGE(" + rec->ip + ")");

  // get the data from execution of expect command

  // first make the tmp file
  char *tempfile=(char *)malloc(64);
  sprintf(tempfile, "/tmp/Bridge-%s.XXXXXX", rec->ip.c_str());

  if(mkstemp(tempfile)<0) {
      perror("get_NO_SNMP_BRIDGE(mkstemp) system call error"); fflush(stderr); 
      unlink(tempfile);
      return;
  }

  string myCommand;
  string myIP=f.fmt_ip(rec->ip);
  string buf("select n.view_pwd ||'|'||coalesce(n.enable_pwd,'-') ||'|'||n.user_id from networks n, l2_switches L where L.l2_ip_addr='" + myIP + "' and L.network_id=n.network_id");
  myComment(myIP + " -- " + buf);

  string buf_str = pq->pq_string(buf);
  list_t words = f.split(buf_str,'|');
  if(words.size() < 3) {
      send_error("---\n\n----\nUnable to get comm strings for " + rec->ip);
      return;
  }
  list_t::iterator w = words.begin();
  string view=*w; w++;
  string enable= f.trim(*w); w++;
  string uid=*w; 

  // USAGE: ./get_bridge.bsh [sw_ip] [view pwd] [enable pwd] [uid]
  char line[1024];  bzero(line, 1024);
  
  if (enable=="-" || enable.length()==0) {
      enable="''";
  }
  sprintf(line, "%s %s %s %s %s > %s", BRIDGE_SCRIPT, rec->ip.c_str(), view.c_str(), enable.c_str(), uid.c_str(), tempfile);
  myComment(rec->ip + " " + line);

  // Execute command
  if(system(line) != 0) {
      cerr << line << endl; fflush(stderr); 
      perror("system call error"); unlink(tempfile);
      return;
  }

  // Open output file for retrieving data [ip, mac] tuples
  //ifstream in_file(tempfile, ios::in);
  ifstream in_file(tempfile, ios::in);
  if(!in_file) {
      send_error("Unable to open input stream -- filename: '" + string(tempfile) + "'"); unlink(tempfile);
      return;
  }

  uint myCounter=0;

  // format vlan mac "dynamic ip,assigned,...,etc." port
  rec->d2=pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");

  while ( ! in_file.eof() )
  {
      // read in the next line
      bzero(line, 1024);
      in_file.getline (line, 1024);
      myComment(rec->ip + " " + line);
      string myS = f.trim(line); 
      if(myS.length()==0) continue;

      list_t theWords = f.split(myS, ' ');
      if(theWords.size()<3) continue;

      list_t::iterator i=theWords.begin();
      string vlan=*i; i++;
      string mac=f.fmt_mac(*i); i++;
      string port=*i;

      if(s->format_port(&port)==0) {
          if(!SILENT) cout << "Failed to format port " << port << endl;
          continue;
      }
      //if (is_uplink(port, myIP)) continue;
      if(rec->IgnorePorts.size() > 0) {
          if(rec->IgnorePorts[port] > 0) continue;
      }

      polling_record *pR = new polling_record();
      pR->mac=mac;
      pR->L3=rec->L3;
      pR->L2 = rec->ip;
      pR->vlan=vlan;
      pR->ifName=port;
      pR->dt2=rec->d2;
      rec->P.push_back(  pR );
      myCounter++;
  }
  if(!myCounter) cout << "Failed to get any bridge data for switch: " << rec->ip << "\n";

  rec->d2=pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  if(DEBUG) cout << "Size of list for " << rec->ip << " is " << rec->P.size() << endl;
  unlink(tempfile); // remove the file from /tmp
}


//----------------------------------------------------
// called by update_ARP_only(dbl_sys_t *St)
// for these system types:
//_CISCO_NO_SNMP_ 
// _FW_ 
// _INSIDE_FW_ 
// _VRF_ 
// _CASA5520_FW_
void get_ARP_to_update_polling(sys_t *rec, int sysType)
{
  // create arp records that already holds unique list of mac addresses, 
  // each of which has a map of [ip,vlan] tuples.

  getARPcache(rec);
      
  for(hash_map<string, arp_record_t *, stringhasher>::iterator iter=rec->A.begin(); iter!=rec->A.end(); iter++) 
  {
      arp_record_t *aRec=iter->second;
      if(!aRec->vlan.length()) {
          cerr << "Unable to get VLAN for this ARP data to update polling: " << aRec->mac << " L3: " << aRec->ip << "\n";
          // discard record....
          continue;
      }

      polling_record *pR = new polling_record();
      pR->mac=aRec->mac;
      pR->L3=rec->L3;
      pR->L2 = rec->ip; // the router's IP Address
      pR->vlan=aRec->vlan;
      pR->ifName="N/A";
      pR->dt2= s->current_timestamp;
      pR->ips=aRec->ips;
      pR->print_poll_record();
      rec->P.push_back(  pR ); // put list into this L2's (rec) polling records.
  }
  rec->d2=pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  if(DEBUG) cout << "Size of list for " << rec->ip << " is " << rec->P.size() << endl;
}


//------------------------------------------------------------------------------------
// called by update_L3_polling()
// only called if it's a FW type system
//------------------------------------------------------------------------------------
void update_ARP_only(dbl_sys_t *St)
{
  cout << "update_arp_only() Get arp only\n";
  //need the enable passwd

  St->S->vlan = pq->pq_string("select vlan from vlans v where l3_name='" + St->S->L3 + "' and vlan!='local'");
  if(DEBUG) cout << "VLAN: " <<  St->S->vlan << " for L3 " <<  St->S->L3 << endl;

  // get arp from expect SCRIPT
  // ----------------------------------------------
  list<sys_t *>::iterator L2_iter;
  if( !St->L2_list || !St->L2_list->size() )  {
      if(!SILENT) cout << "Unable to Update L3 " << St->S->L3 << " --  NO L2 data.\n";
      return;
  }

  for(L2_iter = St->L2_list->begin(); (L2_iter != St->L2_list->end()); L2_iter++) 
  {
      // there should only be one here, but ya never know...
      sys_t *rec = *L2_iter;
      rec->vlan = St->S->vlan;
      rec->L3 = St->S->L3;

      // get telnet/enable passwords from database for the router.
      rec->comm=pq->pq_string("select n.view_pwd ||' '|| n.enable_pwd from networks n, L3_routers L where L.l3_name='" + rec->L3 + "' and L.network_id=n.network_id");
      get_ARP_to_update_polling(rec, St->S->sysType);
      update_L2_poll_time(rec->ip, s->current_timestamp, rec->d2);
      // get arp from 'L2'
      if(DEBUG) cout << ":: next updating polling with " << rec->P.size() << " records\n";
      if( rec->P.size() > 0 ) {
          update_polling(&rec->P);
      } 
      else if(DEBUG) cout << "Not updating POLLING: rec->P.size() <= 0\n";
  }
  string uBuf("update L3_routers set date_last_polled=current_timestamp, date_first_polled = timestamp '"
              + s->current_timestamp + "'where L3_name='"+St->S->L3+"'");
  if(! pq->pq_exec(uBuf) ) send_error(" Unable to update date_polled for " + St->S->L3 );
  else if(!SILENT) cout << "Updated L3 " << St->S->L3 << " date_polled\n";
}


//------------------------------------------------------------------------------
bool is_L2(string L2)
{
  string myS("select count(*) from l2_switches s, l2_networks n where inet(s.l2_ip_addr)= inet('" + L2 + "') and s.l2_ip_addr=n.l2_ip_addr");
  if(DEBUG) cout << myS << "\n";

  int num = pq->pq_count(myS);
  if(num > 0) {
      if(DEBUG) cout << "\tis_L2() returning true\n";
      return true;
  }
  if(DEBUG) cout << "\tis_L2():: returning FALSE\n";
  return false;
}

//------------------------------------------------------------------------------
// ----- check if mac/ip pair stil exists in polling
//------------------------------------------------------------------------------
bool is_same_ip(string mac, string ip)
{
  string myS("select count(*) from polling p, polling_ips i "
             "where p.mac='"+mac+"' and p.mac=i.mac and i.ip_addr='"+ip+"'");
  if(pq->pq_count(myS)>0) return true;
  return false;
}

//------------------------------------------------------------------------------
// populates a polling record with arp data and sends it back.  no db updates.
//------------------------------------------------------------------------------
polling_record * update_polling_with_arp(arp_record_t *aRec, string L3)
{
  if(is_L2(aRec->ip)) {
      if(DEBUG) cout << "update_polling_with_arp(" << aRec->ip << ", " << L3 << ") is a L2 switch, returning 0\n";
      return 0; // not polling network switches
  }

  polling_record *pR = new polling_record();
  string L3_ip = pq->pq_string("select ip_addr from L3_routers where L3_name='" + L3 + "'");

  if(L3_ip.length() > 0 && is_L2(L3_ip)) pR->L2 = L3_ip;
  else {
      send_error("update_polling_with_arp():: no L2_IP_Addr for [mac: " + aRec->mac + ", vlan: " + aRec->vlan + ", L3: " + L3 + "]\n");
      return 0;
  }
  pR->mac=aRec->mac;
  pR->L3=L3;
  pR->vlan=aRec->vlan;
  pR->ifName="N/A";
  pR->dt2= s->current_timestamp;
  pR->ips=aRec->ips;
  return pR;
}



//-----------------------------------------------------------
void print_dangling_arp(string L3, aList_t *A)
{
  cout << "print_dangling_arp()\n";

  vector<polling_record *> pRs;
  string msg;
  for(aList_t::iterator a=A->begin(); a!= A->end(); a++)
  {
      arp_record_t *aRec = a->second;

      // if the polling record had no bridge data... and the ip address is not of a switch
      if(aRec->L2_found==false) {
          polling_record *P = update_polling_with_arp(aRec, L3);
          if(P!=0) pRs.push_back(P);
          else {
              msg += "Vlan\t" + aRec->vlan + "\t" + aRec->mac + "\t";
              for(map_t::iterator i=aRec->ips.begin(); i!= aRec->ips.end(); i++) {
                  msg += i->first + " ";
              }
              msg += "\n";
          }
      } 
  }
  update_polling(&pRs);

  if(DEBUG && msg.length() > 0) cout << "Dangling ARP report:\n-------------------------\n" + msg;
}

//----------------------------------------------------------------------------------------
void *update_L3_polling(void *v)
{
  myComment ("update_L3_polling()");

  dbl_sys_t *St = (dbl_sys_t*) v;
  int ARP_GOT=0;

  if( system_ssh_only(St->S->sysType) ) 
  {
     if(DEBUG) cout << " system_ssh_only:: update_L3_polling(" << St->S->ip << ") calling either (update_ARP_only() & returning St) or  (getARPcache() & staying to get L2);.\n";
     if(is_ARP_only(St->S->sysType) ) {
         update_ARP_only(St);
         return St;
     }
     else {
         getARPcache(St->S);
         if(DEBUG) cout << "getARPcache():  update_L3_polling(" << St->S->ip << ") staying to get L2);.\n";
         ARP_GOT=1;
     }
  }

  int list_size = St->L2_list->size() + 1;  // vector
  if(DEBUG) cout << "Number of threads will be " << list_size << "\n";

  list<sys_t *>::iterator L2_iter;
  aList_t::iterator itera;

  int num=0;
  
  // create threads to get the bridge tables
  pthread_t tid[list_size];
  pthread_attr_t attr;
  pthread_attr_init(&attr);

  if(DEBUG) cout << "\n--\tGetting ARP: " << St->S->ip << "\n";

  if(ARP_GOT==0 || !system_ssh_only(St->S->sysType)) {

      if(DEBUG) cout << "calling thread for get_arp_data()\n"; fflush(stdout);
      int return_val = pthread_create(&tid[num], &attr, get_arp_data,(void *) St->S);
      if(DEBUG) {
          cout << "returned from calling thread for get_arp_data()\n"; 
          cout << "return value=" << return_val << "\n";  // simplify reference to arp data list
          cout << "Size of list is: " << St->S->A.size() << "\n";  // simplify reference to arp data list
          fflush(stdout);
      }

      if(return_val != 0) send_pthread_error(return_val);
      else { 
          NAC_THREADS++;
          num++;
      }
  }

  aList_t *A = &St->S->A;  // simplify reference to arp data list
  if( !St->L2_list || !St->L2_list->size() )  
  {
      print_dangling_arp(St->S->L3, A);
      string uBuf("update L3_routers set date_last_polled=current_timestamp, date_first_polled = timestamp '" 
              + s->current_timestamp + "'where L3_name='"+St->S->L3+"'");
      if(! pq->pq_exec(uBuf) ) send_error(" Unable to update date_polled for " + St->S->L3 );
      else if(!SILENT) cout << "Updated L3 " << St->S->L3 << " date_polled with NO L2 information.....  Hm.\n";
      return 0;
  }

  if(St->L2_list->size() == 1) {
      L2_iter = St->L2_list->begin();
      sys_t *rec = *L2_iter;
      get_bridge_data((void *) rec);
  }
  else {

      for(L2_iter = St->L2_list->begin(); (L2_iter != St->L2_list->end()) && (num < list_size); L2_iter++) 
      {
          sys_t *rec = *L2_iter;
          int return_val = pthread_create(&tid[num], &attr, get_bridge_data, (void *) rec);
          if(return_val != 0) send_pthread_error(return_val);
          else { NAC_THREADS++; num++; }
          cerr << "number of threads: " << num << "\n"; fflush(stdout);
      }

      // wait until joining all threads
      int *status;
      for(int i=0; i<num; i++) {
          if(pthread_join( tid[i], (void **)&status) != 0) 
              cerr << "Error joining thread " << i << endl;
          else NAC_THREADS--;
      }
      // delete memory used for threads
      pthread_attr_destroy(&attr);
  }

  if(DEBUG) {
      cout << "Printing ARP: size:" << A->size() << "\n";
      for(itera=A->begin(); itera!=A->end(); itera++) {
          arp_record_t *aRec = itera->second;
          cout  << "ARP:\t" << aRec->mac << "\t" << aRec->vlan << "\t";
          for(map_t::iterator ip=aRec->ips.begin(); ip!=aRec->ips.end(); ip++) {
              if(ip!=aRec->ips.begin()) cout << ", ";
              cout << ip->first;
          }
	  cout << "\n";
      }
  }

  // map BRIDGE to ARP 
  for(L2_iter=St->L2_list->begin(); L2_iter != St->L2_list->end(); L2_iter++)
  {
      sys_t *rec = *L2_iter;
      update_L2_poll_time(rec->ip, s->current_timestamp, rec->d2);
      vector<polling_record *> *P = &rec->P; // = new pList_t();

      for(vector<polling_record *>::iterator iterb=P->begin(); iterb != P->end(); iterb++) 
      {
          polling_record *pollRec = *iterb;

          itera = A->find( pollRec->mac );
          if(DEBUG) cout << "Mapping mac: " << pollRec->mac  << " between bridge/arp\n";

          if(itera != A->end()) { // if the MAC in the bridge is found in the ARP...
              if (DEBUG) cout << " MAC in the bridge is found in the ARP (" <<  pollRec->mac << ")\n";
              arp_record_t *aRec = itera->second;
              pollRec->ips= aRec->ips;
              if(aRec->vlan.length() >0) pollRec->vlan= aRec->vlan;
                  aRec->L2_found=true;
              if(DEBUG) pollRec->print_poll_record();
          }
          // otherwise, use the ARP data as is (without switch/L2 info...)
      }
      if( P!= 0 && P->size() > 0 ) update_polling(P);
  }

  print_dangling_arp(St->S->L3, A);
  string uBuf("update L3_routers set date_last_polled=current_timestamp, date_first_polled = timestamp '" 
              + s->current_timestamp + "'where L3_name='"+St->S->L3+"'");
  if(! pq->pq_exec(uBuf) ) send_error(" Unable to update date_polled for " + St->S->L3 );
  else if(!SILENT) cout << "Updated L3 " << St->S->L3 << " date_polled\n";

  return (void *)St;
}

//----------------------------------------------------------------------
void set_environs(const char *uid)
{

  if(!SILENT) cout << "set_environs(" << uid << ")\n";
  if (getuid() != 0) {
      cout << "NACpolling -u must be run as root\n\n";
      perror("getuid()");
      exit(1);
  }

  static struct passwd *runas_pw = NULL;

  // change ownership of NACpolling -- this process
  // from root to input parameter, uid 
  //-----------------------------------------------
  runas_pw = getpwnam(uid);

  if (runas_pw == NULL)
  {
      send_error("Unable to runas_pw() for userid " + string(uid) + ": " + strerror(errno));
      perror("getpwnam()");
      exit(1);
  }
  endpwent();

  if (setuid(runas_pw->pw_uid) < 0) {
      send_error("ERROR: Unable to setuid() for uid " + string(uid) + ": " + strerror(errno));
      perror("setuid()");
      exit(1);
  }
  if(!SILENT) cout << "set_environs(" << uid << "):: setuid OK\n";
}


//------------------------------------------------------------
void usage()
{
  cout << "usage: NACd -d -s -o -H -r router[|vlan] -h [-2 switch-ip] \n"
       << "\t-d   debug\n"
       << "\t-s   silent\n"
       << "\t-o   Outpost\n"
       << "\t-H   database host\n"
       << "\t-t   seconds for application life [default = 300]\n"
       << "\t-r   router[:vlan] -- does only polling for this router[vlan]\n"
       << "\t-2   switch_ip:vlan -- does only polling for this switch/vlan:L3 (vlan:L3 required)\n"
       << "\t-h   help (this output)\n"; 
      cout << "\nOutpost: [NACmgr, NAC1, NAC2, NAC3, NAC4, NAC5, NACmgr-alt, test, VW]\n";
      exit(1);
}

//------------------------------------------------------------
void parse_options(int argc, char *argv[])
{
  DEBUG=false;
  SILENT=false;
  FORCE=false;
  DO_SCAN=false;
  OUTPOST=LOCAL_HOST;
  ROUTER="";
  L2_IP_ADDR="";
  DB_HOST=LOCAL_DB_HOST;
  TTL=300;

  if(argc < 2) {
      return;
  }

  for(int i=1; i< argc; i++) 
  {
      char c1 = argv[i][0];
      char c2 = tolower(argv[i][1]);

      if(c1=='-')
      {
          if(c2=='s') { SILENT=true; DEBUG=false; }
          else if(c2=='d') { SILENT=false; DEBUG=true; cout << "Debug Mode\n"; }
          else if(c2=='2' && argc > (i+1) ) { 
              i++;
              cout << "L2_IP_ADDR is " << argv[i] << "\n"; 
              L2_IP_ADDR= f.fmt_upper(string(argv[i]));
	  }
          else if(c2=='r' && argc > (i+1) ) { 
              i++;
              cout << "ROUTER is " << argv[i] << "\n"; 
              ROUTER= f.fmt_upper(string(argv[i]));
          }
          else if(c2=='u') { 
              set_environs( argv[i+1] );
          } 
          else if(c2=='o' && argv[i+1] != NULL)
          {
              OUTPOST=argv[i+1];
              if(  (OUTPOST != "NACmgr")
                && (OUTPOST != "NAC1") 
                && (OUTPOST != "NAC2")
                && (OUTPOST != "NAC3") 
                && (OUTPOST != "NAC4") 
                && (OUTPOST != "NAC5")
                && (OUTPOST != "NACmgr-alt")
                && (OUTPOST != "test")
                && (OUTPOST != "VW") ) 
              {
                  cout << "Unknown Outpost " << argv[2] << endl;
                  cerr << "Unknown Outpost " << argv[2] << endl;
                  usage();
              }
          }
          else if(c2=='H' && (argv[i+1] != NULL) ) { DB_HOST=argv[i+1];}
          else if(c2=='t' && (argv[i+1] != NULL) ) 
          { 
		TTL=atoi(argv[i+1]); 
                if(TTL == 0) { cerr << "invalid TTL : " << argv[i+1] << endl; exit(1); }
                if(TTL > 10000) { cerr << "TTL is too large: " << argv[i+1] << endl; exit(1); }
                if(DEBUG) cout << "TTL set to " << TTL << "\n";
          }
          else if(c2=='h') { usage(); }
          else if(c2=='f') { FORCE=true; }
          cout << "c1: " << c1 << "\tc2: " << c2 << endl;
      }
  }
  if(OUTPOST.length()==0) { cout << "OUTPOST is still undefined\n"; exit(1); }
  if(DB_HOST.length()==0) { cout << "DB_HOST is still undefined\n"; exit(1); }
}

//------------------------------------------------------------------------
string insert_port_conflict_record(polling_record *R)
{
  // does it already exist?  If so, return...
  return "";
  string myS("select count(*) from port_conflicts where mac='"+R->mac+"' and l2_ip_addr='"+R->L2+"' and port='"+R->ifName+"'");
  if(pq->pq_count(myS) > 0) {
      return "";
  }

  myS.clear();
  myS="PORTS CONFLICT:\n";

   string ip;
   if(R->ips.size() > 0) {
          map_t::iterator i= R->ips.begin();
          ip=i->first;
   } else {

      string myS("insert into port_conflicts(mac, ip_addr, l2_ip_addr, port, date_first_polled, date_last_polled) "
                 "values ('"+R->mac+"','"+ip+"','"+R->L2+"','"+R->ifName+"',current_timestamp,current_timestamp)");

      if(!pq->pq_exec(myS)) {
          myS+="Failed to insert polling_rcord into port_conflicts\n";
      }
      else log_record("port-conflict", R->L2+"/"+R->ifName, R->mac, "Vlan-" + R->vlan, R->L3);
  }

  myS += "L2: ";
  myS += R->L2;
  myS += "\tPort: ";
  myS += R->ifName;
  myS += "'\tVlan";
  myS += R->vlan;
  myS += "\t";
  myS += R->mac;
  myS += "\n\n";
  return myS;
}

//-------------------------------------------------------------------
polling_record *create_test_conflict(polling_record *rpR)
{
  polling_record *pR = new polling_record();
  *pR=*rpR;
  cout  << "\n" << pR->mac << " is the dummy\n";
  pR->ifName="GiTest";
  return pR;
}

//--------------------------------------------------------------
// Runs through all the L3 stuff, and sees if there's a conflict
// where a single mac shows up in more than one bridge table
//--------------------------------------------------------------
void check_L2_ports(vector<L3_record *> *L3_list)
{
  cout << "check_L2_ports()\n"; fflush(stdout);

  map<string, polling_record *> MACs;
  pair< map<string, polling_record *>::iterator, bool> result;
  
  string eStr;
  bool orig_DEBUG=DEBUG;

  //Find conflicts and store then in this list
  list<polling_record *>conflicts;
  bool tested=true;
  //bool tested=false;

  for(vector<L3_record *>::iterator iter2=L3_list->begin(); iter2 != L3_list->end(); ++iter2)
  {
      L3_record *L3rec = *iter2;
      for(list<sys_t *>::iterator i=L3rec->L2_list->begin(); i!= L3rec->L2_list->end(); i++)
      {
          sys_t *s = *i;
          vector<polling_record *> polls = s->P;
          vector<polling_record *>::iterator pIter = polls.begin(); 
          if(!tested) {
              polling_record *tR = *pIter;
              polling_record *pR = create_test_conflict(tR);
              polls.push_back( pR );
              pIter = polls.begin(); 
              tested=true;
          }
          for(; pIter != polls.end(); ++pIter)
          {
              polling_record *pR = *pIter;

              if(pR->mac.length() > 0)
              {
                  result = MACs.insert ( make_pair(pR->mac, pR) );  // making list of distinct mac addresses...
                  if(!result.second) {
                      polling_record *R = (result.first)->second;
                      R->L2 = f.fmt_ip(R->L2);
                      pR->L2 = f.fmt_ip(pR->L2);
                      if( R->ifName != pR->ifName || R->L2 != pR->L2 ) {
                          // don't need to care about those w/o ips in this version... 
                          // since it just might be from an uplink port.
                          if(pR->ips.size()!=0) conflicts.push_back(pR);
                          if(R->ips.size()!=0) conflicts.push_back(R);
                      }
                  }
              }
          }
      }
  }
  // now have all the conflicts.  So if there are none, return to calling procedure.
  if(conflicts.size()==0) return;

  // now get the number of distinct ports for each L2 w/conflicts
  map_t L2Ports;
  map_t L2list;

  for(list<polling_record *>::iterator i=conflicts.begin(); i!=conflicts.end(); i++) {
    polling_record *R=*i;
    if(L2list.find(R->L2)!=L2list.end()) L2list[R->L2]++;
    else L2list[R->L2]=1;
    string p=R->L2+"/"+R->ifName;
    if(L2Ports.find(p)!=L2Ports.end()) L2Ports[p]++;
    else L2Ports[p]=1;
  }


  map<string, string> mac_list;

  // find the macs that are part of the uplink port issue...
  for(list<polling_record *>::iterator i=conflicts.begin(); i!=conflicts.end(); i++) 
  {
    polling_record *R=*i;
    string p=R->L2+"/"+R->ifName;
    if(L2Ports[p]>1) {
        mac_list[R->mac]=p;
    }
  }

  for(list<polling_record *>::iterator i=conflicts.begin(); i!=conflicts.end(); i++)
  {
    polling_record *R=*i;
    map<string, string>::iterator fM=mac_list.find(R->mac);

    if(fM==mac_list.end()) {
        // then it's not part of an uplink port issue...
        eStr += insert_port_conflict_record(R);
    }
    else if( L2list[R->L2]>1 ) 
    {
        string p=fM->second;
        string myP(R->L2+"/"+R->ifName);
        if(p!=myP) {
            eStr+= R->mac +" found on "+myP+" -- and "+p+"\t";
            eStr+= f.to_string((int)L2list[R->L2]);
            eStr+= " times -- is this an uplink port???\n";
        }
    }
  }
  DEBUG=orig_DEBUG;
  send_error(eStr);
}

//--------------------------------------------------
bool quarantine_type(string ip)
{
  if(ip.substr(0, 3) !=  "010") return false;
  if(ip.substr(0, 7) == "010.008" ) return true;
  if(ip.substr(0, 7) == "010.009" ) return true;
  if(ip.substr(0, 7) == "010.010" ) return true;
  if(ip.substr(0, 7) == "010.011" ) return true;
  return false;
}

//---------------------------------------------------------------------------
// Procedure takes the currently parolled mac addresses, determines the last 
// used IP address and sets it up for a scan...  The record is then deleted 
// from the 'parolled_macs' table.
//-----------------------------------------------------------------------------
void check_remediation_macs()
{
  orDB *db= new orDB();
  db->db_open();

  string myBuf("select mac from opr$hlm.paroled_macs");
  map_t mac_list = db->get_list (myBuf.c_str());

  if(mac_list.size() == 0) return;

  for(map_t::iterator iter=mac_list.begin(); iter!=mac_list.end(); iter++)
  {
     string mac = iter->first;

      myBuf = "select ip_addr from polling_ips i, polling p where p.mac='" + mac + "' "
              "and cast(current_timestamp-p.date_last_polled as interval) < cast('00:05:00' as interval) "
              "and p.mac=i.mac";
      // and i.ip_addr not like '010.008.%' and  i.ip_addr not like '010.009.%' " "and  i.ip_addr not like '010.010.%' and  i.ip_addr not like '010.011.%'";

      map_t ip_list = pq->pq_list(myBuf);

      if(ip_list.size() > 0)
      {
          map_t::iterator i = ip_list.begin();
          string ip = i->first;
          add_to_scan_queue(mac, ip, "current_timestamp");

          if(!SILENT) cout << "Adding to scan queue from parolled: " << mac << endl;

          myBuf="delete from  opr$hlm.paroled_macs where mac = '" + mac + "'";

          if( !db->db_exec(myBuf.c_str()) ) {
              myBuf="rollback";
              db->db_exec(myBuf.c_str());
              send_error("Unable to delete paroled_macs");
          }
          else if(!SILENT) cout << "Deleted from parolled: " << mac << endl;
      }
  }
  db->db_close();
  delete db;
  db=0;
}

//-----------------------------------------------------------------------------
map_t get_vlans_for_L3(string L3_name)
{
  string myS("select distinct vlan from vlans where L3_name = '" + L3_name + "' and status!='OFF-LINE' order by vlan");
  map_t myVlans= pq->pq_list(myS);
  return myVlans;
}

//------------------------------------------------------------------------
list<sys_t *> *get_L2_list(string router, string vlan)
{
  list<sys_t *> *L2_list = new list<sys_t *>();
  string L3 = f.fmt_upper(router);

  /*get L2_Switches from database that have L3 name of [L3rec->L3sys.L3] */
  string myS("select L2_ip_addr||'|'||systype||'|'||network_id FROM L2_switches where L2_ip_addr in (");
  if(vlan.length() > 0) {
      myS += "select L2_ip_addr from l2_networks n, vlans v where upper(v.L3_name)=upper('" + L3 + "') ";
      myS += "and v.status != 'OFF-LINE' and v.vlan_id = n.vlan_id "; 
      myS += "and (v.vlan='" +vlan + "' or v.l2_vlan='" + vlan + "'))";
      myS += "and status != 'OFF-LINE' ";
  }
  else {
      myS += "select L2_ip_addr from l2_networks n, vlans v where upper(v.L3_name)=upper('" + L3 + "') ";
      myS += "and v.vlan_id = n.vlan_id and v.vlan != 'local' and v.status != 'OFF-LINE') and status != 'OFF-LINE' ";
  }

  list_t *L2data = pq->pq_list_t( myS.c_str() );

  if(L2data == 0) {
      myComment(myS);
      cerr << myS << "\nERROR:\n\tNo L2 data found for " <<  L3 << "\n\n";
      return L2_list;
  }


  for(list_t::iterator i=L2data->begin(); i != L2data->end(); i++)
  {
      list_t words = f.split(*i, '|');
      if(words.size() != 3) continue;
      list_t::iterator w=words.begin();

      sys_t *L2_rec = new sys_t();
      L2_rec->L3=L3;

      L2_rec->ip = f.fmt_ip_for_network(*w);
      string ip = *w; w++;

      string sysType=*w;
      L2_rec->sysType = atoi( (*w).c_str()); w++;

      L2_rec->comm = pq->pq_string("select comm_string from networks where network_id='" + *w + "'");

      /* attach vlans this switch is associated*/
      string myBuf("select distinct v.L2_vlan from L2_networks n, vlans v "
                   "where n.l2_ip_addr = '" + ip + "' and n.vlan_id = v.vlan_id "
                   "and L3_name = '" + L3 + "' and v.vlan != 'local' and v.status != 'OFF-LINE'");
      map_t R= pq->pq_list(myBuf);
      if(!R.size()) {
          myComment(myBuf);
          myComment("No vlans found for L2 " + ip);
          continue;
      }
      for(map_t::iterator d=R.begin(); d != R.end(); d++) {
          if(d==R.begin()) L2_rec->vlan=d->first;
          L2_rec->vlans[d->first]= 1;
      }
      
      /* attach ignore ports*/
      myBuf = "select port from ignore_ports where inet(l2_ip_addr) = inet('" + ip + "')";
      L2_rec->IgnorePorts = pq->pq_list(myBuf);
      for(map_t::iterator i= L2_rec->IgnorePorts.begin(); i!= L2_rec->IgnorePorts.end(); ++i)
          L2_rec->IgnorePorts[i->first]=1;

      L2_list->push_back(L2_rec);
  }
  return L2_list;
}


//-----------------------------------------------------------------------
vector<L3_record *> *get_L3_Routers()
{
  myComment("get_L3_Routers()");

  string myS("select l3.ip_addr, n.comm_string, l3.L3_name, l3.ipv6_ready FROM L3_routers L3, networks n "
             "where n.network_id = L3.network_id and upper(L3.outpost) = upper('" + OUTPOST + "') "
             "and L3.status != 'OFF-LINE' order by l3.L3_name");
  myComment(myS);

  dataRow_t *L3_list = pq->pq_rows(myS);

  if(L3_list == 0 || L3_list->size()==0) {
      if(!SILENT) cerr << myS << "\nERROR:\n\tNo L3 data found\n\n";
      return 0;
  }
  myComment(L3_list->size() + " records retrieved");

  vector<L3_record *> *L3_Routers = new vector<L3_record *>();
  L3_Routers->reserve( L3_list->size() + 2);

  /* for each L3_router, get the router's information */
  for(dataRow_t::iterator iter=L3_list->begin(); iter != L3_list->end(); iter++)
  {
      dataRow *dR = (*iter).second;
      L3_record *L3rec = new L3_record();

      list<string>::iterator i=dR->sList.begin();
      L3rec->L3sys.ip = f.fmt_ip_for_network(*i);

      if(++i!=dR->sList.end()) L3rec->L3sys.comm = *i;
      if(++i!=dR->sList.end()) L3rec->L3sys.L3 = *i;
      if(++i!=dR->sList.end()) L3rec->L3sys.ipv6_ready = *i;

      L3rec->L3sys.sysType = pq->pq_count("select systype from L3_routers where L3_name='" +  L3rec->L3sys.L3 + "'");
      L3rec->L3sys.vlans = get_vlans_for_L3(L3rec->L3sys.L3);
      map_t::iterator m=L3rec->L3sys.vlans.begin();
      L3rec->L3sys.vlan = m->first;

      L3rec->L2_list = get_L2_list(L3rec->L3sys.L3, "");

      L3_Routers->push_back(L3rec);
      myComment(L3rec->L3sys.L3);
  }
  if(DEBUG) cout << "leaving get_L3_routers(), with " << L3_Routers->size() << " routers in a list called L3_Routers\n";
  return L3_Routers;
}


/* 
 * --------------------------------------------
 */
void do_L2_polling()
{
  NAC_THREADS=0;
  cout << "doing NAC Polling on the switch " << L2_IP_ADDR << "\n"; 

  s = new snmpRec();
  s->current_timestamp = pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  if(s->current_timestamp.length()==0) {
       cout << "ERROR: Unable to get current timestamp\n";
       exit(1);
  }

  list_t myStrings=f.split(L2_IP_ADDR, ':');
  if(myStrings.size() != 3) usage();
  list_t::iterator i=myStrings.begin();
  sys_t *rec=new sys_t();
  string l2_ip =f.fmt_ip(*i); 
  rec->ip = f.fmt_ip_for_network(*i); i++;
  rec->vlan=*i; i++;
  rec->L3= f.fmt_upper(*i);

  string myBuf("select systype from L2_switches where l2_ip_addr='"+l2_ip+"'");
  rec->sysType=pq->pq_count(myBuf);
  cout << myBuf << endl;

  myBuf="select count(distinct vlan_id) from vlans where vlan='" + rec->vlan + "' and l3_name='" + rec->L3 + "'";
  cout << myBuf << endl;

  int num = pq->pq_count("select count(distinct vlan_id) from vlans where vlan='" + rec->vlan + "' and l3_name='" + rec->L3 + "'"); 
  if(num == 0) {
      cout << "network is undefined: " <<  L2_IP_ADDR << "\n";
      return;
  }
  if(num > 1) {
      cout << "network is multiply defined (I'm confused): " <<  L2_IP_ADDR << "\n";
      cout << myBuf << endl;
      return;
  }
  cout << "Polling switch " << rec->ip << "on vlan " << rec->vlan << "/" << rec->L3 << "\n";
  rec->vlan_id = pq->pq_count("select distinct vlan_id from vlans where vlan='" + rec->vlan + "' and l3_name='" + rec->L3 + "'"); 
  rec->vlans.insert(make_pair(rec->vlan, 0));
  rec->comm = pq->pq_string("select n.comm_string from networks n, l2_switches s where s.l2_ip_addr='"+l2_ip+"' and s.network_id=n.network_id");

  /* attach ignore ports*/
  myBuf = "select port from ignore_ports where inet(l2_ip_addr) = inet('" + l2_ip + "')";
  rec->IgnorePorts = pq->pq_list(myBuf);
  for(map_t::iterator i= rec->IgnorePorts.begin(); i!= rec->IgnorePorts.end(); ++i)
      rec->IgnorePorts[i->first]=1;

  /* get bridge data for the switch and print it out */
  if(system_ssh_only (rec->sysType) ) { 
      cout << rec->ip << ":  System is SSH ONLY\n";
      get_NO_SNMP_BRIDGE(rec);
  }
  else cout << rec->ip << " NOT ssh only type: " << rec->sysType << endl;

  if(get_bridge_data((void *) rec)==0) {
      cout << "get_bridge_data() returned 0 : " <<  L2_IP_ADDR << "\n";
      return;
  }

  for(vector<polling_record *>::iterator iterb=rec->P.begin(); iterb != rec->P.end(); iterb++)
  {
      polling_record *pR = *iterb;
      pR->print_poll_record();
  }
}


//-------------------------------------------------------------
void do_ROUTER_polling()
{
  NAC_THREADS=0;
  cout << "doing NAC Polling on the router " << ROUTER << "\n"; 

  list_t myStrings=f.split(ROUTER, ':');
  string vlan;

  if(myStrings.size()>2) usage();

  if(myStrings.size()==2) {
      ROUTER=myStrings.front();
      vlan=myStrings.back();
      cout << "Polling router " << ROUTER << "on vlan " << vlan << "\n";
  }
  else cout << "Polling router " << ROUTER << "\n";

  s = new snmpRec();
  s->current_timestamp = pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  if(s->current_timestamp.length()==0) { 
       cout << "ERROR: Unable to get current timestamp\n"; 
       exit(1); 
  }
  myComment(s->current_timestamp);

  /* get network information from NAC database (includes L2 list and data) */
  string myS("select ip_addr||'|'||network_id||'|'||ipv6_ready||'|'||sysType FROM L3_routers where upper(l3_name)= upper('" + ROUTER + "') and status != 'OFF-LINE'");
  string myRetStr=pq->pq_string( myS.c_str());
  if(!myRetStr.length()) {
      cout << "Failed to find Router Information\n";
      return;
  }
  list_t words=f.split(myRetStr, '|');
  if(words.size() != 4) {
      cout << "Failed to retrieve Router Information\n";
      return;
  }

  list_t::iterator w = words.begin();

  L3_record *L3rec = new L3_record();
  L3rec->L3sys.L3=ROUTER;
  L3rec->L3sys.ip = f.fmt_ip_for_network(*w);
  w++;
  L3rec->L3sys.comm = pq->pq_string("select comm_string from networks where network_id='" + *w + "'");
  w++;
  L3rec->L3sys.ipv6_ready=*w; w++;
  L3rec->L3sys.sysType = atoi ((*w).c_str()); 
  cerr << ROUTER << ": L3 Systype = " << *w << " (" << L3rec->L3sys.sysType << ")\n";

  if(vlan.length() > 0) {
      L3rec->L2_list = get_L2_list(ROUTER, vlan);
      L3rec->L3sys.vlans[vlan]=1;
      L3rec->L3sys.vlan = vlan;
  } 
  else {
      L3rec->L2_list = get_L2_list(ROUTER, "");
      L3rec->L3sys.vlans = get_vlans_for_L3(L3rec->L3sys.L3);
      map_t::iterator m=L3rec->L3sys.vlans.begin();
      L3rec->L3sys.vlan = f.trim(m->first);
      cerr << L3rec->L3sys.vlan << " is the vlan for the router\n";
  }

  dbl_sys_t *St = new dbl_sys_t();
  St->L2_list = L3rec->L2_list;
  St->S = &L3rec->L3sys;
  cout << "\t#comm" + L3rec->L3sys.comm + "\n";

  if(DEBUG) {
      cout << "\t#Router:" << L3rec->L3sys.L3 << "=ROUTER\n";
      cout << "\t#ip:" + L3rec->L3sys.ip << "\n";
      cout << "\t#comm" + L3rec->L3sys.comm + "\n";
      cout << "\t#ipv6_ready:" << L3rec->L3sys.ipv6_ready << "\n";
      cout << "\t#systype:"; cout << L3rec->L3sys.sysType << "\n";
  }

  update_L3_polling((void *)St);

  vector<L3_record *> *L3_Routers = new vector<L3_record *>();
  L3_Routers->push_back(L3rec);

  check_L2_ports(L3_Routers);
}

//----------------------------------------------------------------------
void do_polling()
{
  if(!pq->pq_exec("update monitor set start_time = current_timestamp where task='" + taskID + "'")) 
      cerr << "Warning: Unable to update monitor start_time for taskID=" << taskID << endl;

  NAC_THREADS=0;
  struct timeval now, later;
  struct timezone tz;
  struct tm *tm;

  gettimeofday(&now, &tz);

  s = new snmpRec();
  s->current_timestamp = pq->pq_string("select to_char(current_timestamp, 'YYYY-MM-DD:HH24:MI:SS')");
  if(s->current_timestamp.length()==0) { 
       cout << "ERROR: Unable to get current timestamp\n"; 
       exit(1); 
  }
  myComment(s->current_timestamp);

  /* get network information from NAC database (includes L2 list and data) */
  vector<L3_record *> *L3_Routers = get_L3_Routers();

  if(!L3_Routers->size()) {
      cerr << "No routers defined for Outpost\n";
      return;
  }
 
  if(L3_Routers->size() == 1)
  {
      vector<L3_record *>::iterator iter2=L3_Routers->begin();
      L3_record *L3rec = *iter2;
      dbl_sys_t *St = new dbl_sys_t();
      St->L2_list = L3rec->L2_list;
      St->S = &L3rec->L3sys;
      update_L3_polling(St);
  }
  else {

      pthread_t tid[L3_Routers->size()];
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      int num=0;
  
      /* for each router */
      for(vector<L3_record *>::iterator iter2=L3_Routers->begin(); iter2 != L3_Routers->end(); ++iter2)
      {
          L3_record *L3rec = *iter2;
    
          if(DEBUG) { 
              cout << "\n-----L3 iterator: " << L3rec->L3sys.L3 << "\n(" << NAC_THREADS << ")-------\n";  
              fflush(stdout); 
          }
    
          if( L3rec->L2_list && L3rec->L2_list->size() ) 
          {
              dbl_sys_t *St = new dbl_sys_t();
              St->L2_list = L3rec->L2_list;
              St->S = &L3rec->L3sys;
       
              int return_val = pthread_create(&tid[num++], &attr, update_L3_polling, (void *)St);
    
              if(return_val != 0) { 
                   send_pthread_error(return_val);
                   clean_up();
                   exit(1); 
              }
              NAC_THREADS++;
              if(DEBUG) cout << "Now have this many threads: " << NAC_THREADS << "\n"; fflush(stdout);
          }
      }
    
      /* wait until joining all threads */
      for(int i=0; i<num; i++) {
          int *status;
          if(pthread_join( tid[i], (void **)&status) != 0) cerr << "Error joining thread " << i << endl;
          else NAC_THREADS--;
      }
      /* delete memory used for threads */
      pthread_attr_destroy(&attr);
  }

  gettimeofday(&later, &tz);
  tm = localtime(&later.tv_sec);
  uint sec = later.tv_sec - now.tv_sec;

  char t[16]; sprintf(t, "%d", (int)sec);
  string uBuf("update outposts set date_last_polled = current_timestamp, poll_time=" + string(t) + 
              " where outpost='"+OUTPOST+"'");

  if(! pq->pq_exec(uBuf) ) send_error (" Unable to update date_last_polled for "+OUTPOST);
  else if(!SILENT) cout << "Updated OUTPOST " << OUTPOST << " date_last_polled\n";

  remove_lock();

  uint usec = later.tv_usec - now.tv_usec;
  if(!SILENT) printf("%d.%03d\n", sec, (usec)/1000);

  check_L2_ports(L3_Routers);

  if(!pq->pq_exec("update monitor set date_last_executed = current_timestamp where task='" + taskID + "'")) 
      cerr << "Warning: Unable to update monitor date_last_executed for taskID=" << taskID << endl;
}


//------------------------------------------------------------
// forks new process (for alarm to work)
//------------------------------------------------------------
void do_NACpolling()
{
  pid_t pid;

  if ((pid = fork()) == -1) { // error occurred
      send_error("do_NACpolling():: unable to fork().  " + string(strerror(errno)));
      fflush(stdout);
      return;
  }

  else if (pid == 0) //child
  {
      //places a signal alarm on this thread only...
      uint counter=0;
      while(counter++ < 20 && !lock_application()) 
      {
          cerr << "... sleeping for 15 seconds\n";
          sleep(15);
      }
      // do the polling task defined by taskID
      do_polling();
      exit(1);
  }
  int status;
  wait(&status);  // wait() returns status
  return;
}

//-------------------------------------------------------------------------------------
void update_MONITOR_taskID()
{
  pid_t pid=getpid();

  char myPID[8];
  sprintf(myPID, "%d", (int) pid);

  string myBuf("update monitor set pid = '" + string(myPID) + "' where task='" + taskID + "'");

  if(pq->pq_exec(myBuf)==0) {
      cout << "\n--->> ERROR update_MONITOR_taskID\n-- \t" << myBuf << endl; fflush(stdout);
      clean_up();
      exit(1);
  }
}

//----------------------------------------------------------------
int main(int argc, char *argv[])
{
  if(argc < 2)  usage();
  signal(SIGPIPE, SIG_IGN);

  parse_options(argc, argv);
  if(ROUTER.length() > 0) {
      if(!open_NAC_db()) cerr << "Failed to open NAC database\n";
      else do_ROUTER_polling();
      clean_up();
      return 0;
  }
  if(L2_IP_ADDR.length()>0) {
      if(!open_NAC_db()) cerr << "Failed to open NAC database\n";
      else do_L2_polling();
      clean_up();
      return 0;
  }

  if(OUTPOST == "NACmgr") taskID="NP";
  else if(OUTPOST == "NAC1") taskID="NP1";
  else if(OUTPOST == "NAC2") taskID="NP2";
  else if(OUTPOST == "NAC3") taskID="NP3";
  else if(OUTPOST == "NAC4") taskID="NP4";
  else if(OUTPOST == "NAC5") taskID="NP5";
  else if(OUTPOST == "NACmgr-alt") taskID="NACalt";
  else if(OUTPOST == "test") taskID="test";
  else if(OUTPOST == "VW") taskID="VW";
  else {
      cerr << "Unable to derive TASKID from Outpost\n";
      usage();
  }
  if(FORCE) {
      if(open_NAC_db()) 
      {
          if(!SILENT) cout << "NACpolling -o " << OUTPOST << " is now on_task\n";
          do_NACpolling();
      } 
      else cerr << "Failed to open NAC database\n";
      clean_up();
      return 0;
  }
  else cout << "FORCE is off\n";

  if(open_NAC_db()) update_MONITOR_taskID();
  else {
      cerr << "Unable to open NAC database\n"; 
      exit(1); 
  }

  while(1) 
  {
      if(open_NAC_db()) 
      {
          if(!on_task(taskID)) sleep(15);
          else {
             if(!SILENT) cout << "NACpolling -o " << OUTPOST << " is now on_task\n";
             do_NACpolling();
          }
          pq->pq_close();
      }
  }
  clean_up();
  return 0;
}
