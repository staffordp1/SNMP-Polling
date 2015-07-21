#include "poll_driver.hpp"

extern void myComment(string);

typedef hash_map<string, polling_record *, stringhasher> pList_t;
typedef hash_map<string, arp_record_t *, stringhasher> aList_t;
typedef hash_map<string, string *, stringhasher> walkRecord_t;
typedef map<string, int> map_t;
typedef walkRecord_t::iterator iter_h_t;
typedef hash_map<string, polling_record *, stringhasher> pHash_t;


//-------------------------------------------------
bool get_L2_id (string vlan, string L3, string ip, string *L2_id)
{
  if(vlan.length()==0 || L3.length()==0 || ip.length()==0) 
  {
      if(vlan.length()==0) cout << "ERROR: get_L2_id( vlan is NULL )\n";
      else if(L3.length()==0) cout << "ERROR: get_L2_id( L3 is NULL )\n"; 
      else if(ip.length()==0) cout << "ERROR: get_L2_id( ip is NULL )\n"; 
      return false;
  }

  fmt f;
  vlan = f.trim(vlan);

  string myS("select count(*) from L2_networks n, vlans v where inet(n.L2_ip_addr) = inet('"+ ip +"') and "
             "(v.vlan='"+vlan+"' or v.L2_vlan='" + vlan + "') and v.L3_name='"+L3+"' and v.vlan_id=n.vlan_id ");

  if(!pq->pq_count(myS)) {
      if(!SILENT) cout << "ERROR: get_L2_id():\n\t" << myS << endl;
      return false;
  }

  myS="select  n.L2_id from L2_networks n, vlans v where inet(n.L2_ip_addr) = inet('"+ ip +"') and "
      "(v.vlan='"+vlan+"' or v.L2_vlan='" + vlan + "') and v.L3_name='"+L3+"' and v.vlan_id=n.vlan_id ";

  int num = pq->pq_count(myS);
  if(num <= 0) {
      if(!SILENT) cout << "ERROR: get_L2_id()\n\t" << myS << endl;
      return false;
  }
  *L2_id = f.to_string(num);
  if(DEBUG) cout << " L2_id = " << *L2_id << "\n";
  return true;
}


// this gives more information than polling_record::print_poll_record(), 
// and sends an email.
void print_polling_record_error(polling_record *pR, string ip, string msg)
{
  if(SILENT) return;
  if(!pR) return;

  string myMsg=(msg + "<pre>\n\tL3: "+ pR->L3 + "\n");
  myMsg +="\tvlan: "+ pR->vlan + "\n";
  myMsg += "\tL2: "+ pR->L2 + "\n";
  myMsg += "\tmac: "+ pR->mac + "\n";
  myMsg += "\tport: " + pR->ifName + "\n";
  myMsg += "\tIp: " + ip + "\n";
  cout << "\n" << myMsg << "\n</pre>";
  send_error(myMsg);
}


// Add RECORD to the polling table
// [mac, port, date_first_polled, date_last_polled, l2_id]
bool insert_polling_record(string mac, string L2_id, string ifName)
{
  string d_str ("', TIMESTAMP '" + s->current_timestamp + "', TIMESTAMP '" + s->current_timestamp + "', '");
  string myS ("insert into polling (mac, date_first_polled, date_last_polled, port, L2_id) values ('" 
              + mac + d_str + ifName + "', " + L2_id + ")");
  if(pq->pq_exec(myS) == false) {
      if(!SILENT) cout << "\nERROR: add_to_polling()\n\t" << myS << "\n";
      return false;
  }
  if(DEBUG) cout << "Inserted polling record(" << mac << ", " << ifName << ", " << L2_id << ")\n";
  return true;
}

//----------------------------------------------------------------
// add mac polling information to both polling and polling_ips.
bool add_to_polling(polling_record *pR)
{
  if(DEBUG) cout << "add_to_polling() -- begin\n";

  if(pR==0) {
      if(!SILENT) cout << "\tpR==NULL\n";
      return false;
  }
  string L2_id;
  if(!get_L2_id(pR->vlan, pR->L3, pR->L2, &L2_id)) {
      print_polling_record_error(pR, "--", "Failed to get L2_id for network");
      return false;
  }

  pR->L2_id = atoi ( (char *)L2_id.c_str());
  
  if(!insert_polling_record(pR->mac, L2_id, pR->ifName)) {
      print_polling_record_error(pR, "--", "Failed to insert first polling record for mac");
      return false;
  }

  fmt f;

  // insert polling_ips
  for(map_t::iterator m = pR->ips.begin(); m!= pR->ips.end(); m++) 
  {
      string ip = f.fmt_ip(m->first);
      string myS ("insert into polling_ips (mac, ip_addr) values ('" + pR->mac + "', '" + ip + "')");
      if( !pq->pq_exec(myS)) {
          print_polling_record_error(pR, ip, "error inserting polling_ip record\n" + myS + "\n");
          continue;
      } 
      if(DEBUG) cout << "Inserted polling_ips record(" << pR->mac << ", " << ip << ")\n";
  }
  return true;
}


//------------------------------------------------------------------------
// Only one polling record exists with this mac address in polling table.
// If duplicate records, then there's a problem somewhere.
// mac is the primary key in postgreSQL polling table
//------------------------------------------------------------------------
bool get_polling_record(string the_mac, polling_record *pR)
{
  fmt f;
  if(DEBUG) cout << "get_polling_record()\n";

  string mac = f.fmt_mac(the_mac);
  if( !mac.length()) {
      if(!SILENT) cout << "ERROR get_polling_record() :: MAC is empty or NULL" << endl;
      return false;
  }
  string *myS = new string("select p.mac, p.port, n.vlan_id, v.vlan, n.L2_ip_addr, "
                          "v.L3_name, to_char(p.date_last_polled, 'YYYY-MM-DD:HH24:MI:SS'), "
                          "to_char (p.date_first_polled, 'YYYY-MM-DD:HH24:MI:SS'), p.l2_id "
                          "from polling p, L2_networks n, vlans v "
                          "where p.mac='" + mac + "' and p.L2_id=n.L2_id and n.vlan_id=v.vlan_id");

  dataRow_t *myData = pq->pq_rows(*myS);  
  if(myData == 0 || myData->size()==0) {
      if(DEBUG) { cout << "\tNo polling records found\n\t" << *myS << endl; fflush(stdout); }
      return false;
  }

  dataRow_t::iterator iter = myData->begin();
  dataRow *dR = iter->second;

  if(dR->sList.size() != 9) {
      if(DEBUG) cout << "ERROR: " << dR->sList.size() << "columns retrieved -- bad polling record for " << mac << endl;
      return false;
  }
  list<string>::iterator i;
  i=dR->sList.begin(); 
  pR->mac = *i; i++; //mac
  pR->ifName = *i; i++; //port
  pR->vlan_id = (unsigned int) atoi( (*i).c_str()); i++; //vlan_id
  pR->vlan = *i; i++; //vlan
  pR->L2 = *i; i++; //L2_ip_addr
  pR->L3 = *i; i++; // L3_name
  pR->dt2 = *i; i++; // date_last_polled
  pR->dt1 = *i; // date_first_polled
  pR->L2_id = atoi ( (char *) (*i).c_str()); // date_first_polled

  pR->ips = pq->pq_list("select ip_addr from polling_ips where mac='" + pR->mac + "'");
  for(map_t::iterator m=pR->ips.begin(); m!=pR->ips.end(); m++) m->second= atoi (pR->vlan.c_str());
  if(DEBUG) cout << "\tget_polling_record():  -- returning true --\n";
  return true;
}

//-------------------------------------------------
bool update_polling_time(string mac)
{
  string myS ( "update polling set date_last_polled=current_timestamp where mac='" + mac + "'");
  if(pq->pq_exec(myS) == false) {
      if(!SILENT) cout << "\ttroubles with update: " << "\t" << myS << endl; 
      return false;
  } 
  if(DEBUG) cout << "\tupdate_polling_time(): OK " << mac << "\n";
  return true;
}

//-------------------------------------------------
bool update_history_time(string id, string dt)
{
  string myS("update polling_history set date_last_polled= TIMESTAMP '" + dt + "' where poll_id=" + id);
  if(pq->pq_exec(myS) == false) {
      if(!SILENT) cout << "troubles with update_history_time: " << "\t" << myS << endl;
      return false;
  }
  if(DEBUG) cout << "\tupdate_history_time(): OK\n";
  return true;
}


//-------------------------------------------------
bool defined_in_history(string mac, string L2, string vlan)
{
  if(DEBUG) cout << "defined_in_history()\n";
  string myS("select count(*) from polling_history where mac='" + mac + "' and inet(L2_ip_addr)= inet('" + L2 + "') and vlan='" + vlan + "'");
  if(pq->pq_count(myS)) {
      if(DEBUG) cout << "\tReturing true\n";
      return true;
  }
  if(DEBUG) cout << "\tdefined_in_history(): Returing false\n\t" << myS << "\n";
  return false;
}


//-----------------------------------------------------------------------------------
// called only from archive_polling()
// Now, need both mac and l2_id.
bool get_last_history(string mac, polling_record *pR)
{
  myComment("get_last_history("+pR->mac+", "+pR->L2+", "+pR->vlan+")\n");

  if(!pR->vlan.length()) {
      if(SILENT) return false;
      cout << "WARNING:  get_last_history(VLAN MIssing from polling_record) for " << mac << "\n";
      pR->print_poll_record();
      return false;
  }

  string myQuery ("select max(poll_id) from polling_history where mac='" + mac + "' and date_last_polled=");
  myQuery += "(select max(date_last_polled) from polling_history where mac='" + mac + "')";
  // this is the very last record created for this mac....  
  // the network and port are not relevant at this time. 
  // there may be more than one poll_id defined for this mac at this particular last polled time....
  // so, this max(ID) has no relevance to the poll_id in general.

  pR->id = (unsigned int) pq->pq_count(myQuery);
  if( pR->id <= 0) {
      if(!SILENT) cout << "get_last_history()\n\tNo history records found"<< myQuery << endl;
      return false;
  }

  fmt f;
  string poll_id = f.to_string(pR->id);
  string myS ("select mac, port, l2_ip_addr, vlan, l3_name, to_char(date_last_polled, 'YYYY-MM-DD:HH24:MI:SS') "
       "as date_last_polled, to_char(date_first_polled, 'YYYY-MM-DD:HH24:MI:SS') as date_first_polled "
       "from polling_history where poll_id = " + poll_id);

  dataRow_t *myData = new dataRow_t;
  myData = pq->pq_rows(myS);

  if(myData == 0 || myData->size()==0) {
      send_error("get_last_history(): (No rows found) although poll_ID retrieved.\n" + myS + "\n--\n" + myQuery + "\n");
      if(DEBUG) {
          cout << "\tWARNING:\nget_last_history(): (No rows found) although poll_ID retrieved!\n";
          cout << "polling_history query:\n\t" << myS << "\nPollID query:\n\t" << myQuery << "\n";
      }
      return false;
  }

  dataRow_t::iterator iter = myData->begin();
  dataRow *dR = (*iter).second;
  if(dR == 0 || dR->sList.size() != 7) {
      if(DEBUG) cout << "\tdR->sList size is not 7 -- returning FALSE --\n";
      return false;
  }
  list<string>::iterator i;
  i=dR->sList.begin();

  pR->mac = *i; i++;
  pR->ifName = *i; i++;
  pR->L2 = *i; i++;
  pR->vlan = *i; i++;
  pR->L3 = *i; i++;
  pR->dt2 = *i; i++;
  pR->dt1 = *i; 

  myS.clear();
  myS = "select count(ip_addr) from history_ips where poll_id = " + poll_id;
  if(pq->pq_count(myS) > 0) 
  {
     pR->ips= pq->pq_list("select ip_addr from history_ips where poll_id = " + poll_id);
     if(pR->ips.size() <= 0) {
         if(!SILENT) cout << "ERROR obtaining ip addresses from history for " << pR->mac << ", id=" << pR->id << endl;
         return false;
     }
  }
  else if(DEBUG) cout << "\nERROR? get_last_history(): No history_IPs found\n\t" << myS << endl;

  if(DEBUG) cout << "\tget_last_history(): OK\n";
  return true;
}


//---------------------------------------------------------
bool insert_history(polling_record *p)
{
  if(DEBUG) cout << "insert_history()\n";

  string dt1(" TIMESTAMP '" + p->dt1 + "'");
  string dt2(" TIMESTAMP '" + p->dt2 + "'");

  int poll_id = pq->pq_count("select NEXTVAL('poll_id')");

  if(poll_id <=0) {
      if(!SILENT) cout << "\t" << "Error retrieving poll_id\n";
      return false;
  }

  fmt f;

  string myID = f.to_string(poll_id);

  string myS("insert into polling_history (poll_id, mac, port, vlan, l2_ip_addr, "
             "l3_name, date_first_polled, date_last_polled) values (" + myID +
             ", '" + p->mac + "', '" + p->ifName +  "', '" + p->vlan 
             + "', '" + p->L2 + "', '" + p->L3 + "', " + dt1 + ", " + dt2 + ")"); 

  if( !pq->pq_exec(myS)) {
      if(DEBUG) cout << "\t" << myS << "\n\tReturning -- FALSE --\n";
      return false;
  }

  // insert history_ips
  for(map_t::iterator m = p->ips.begin(); m!= p->ips.end(); m++) 
  {
      string ip = f.fmt_ip(m->first);
      if( ip.length() > 0) {
          myS = "insert into history_ips (poll_id, ip_addr) values (" + myID + ", '" + ip + "')";
          if(!pq->pq_exec(myS)) {
              if(!SILENT) cout << "\tERROR Updating history_ips: \n\t"<< myS << "\n";
              return false;
          }
      }
      else {
          if(!SILENT) cout << "\tERROR Updating history_ips: ip.length() <=0 (" << m->first << ")\n";
      }
  }
  if(DEBUG) cout << "\t" << "insert_history():: OK\n";
  return true;
}

//----------------------------------------------------------------------
// called from update_polling() only
//----------------------------------------------------------------------
bool archive_polling(polling_record *p)
{
  myComment("archive_polling("+p->mac+", "+p->L2+", "+p->vlan+")");

  if(!defined_in_history(p->mac, p->L2, p->vlan)) // this is the current polling record for the mac 
  {
      if(insert_history(p)) {
          myComment("Successfuly inserted history record ["+ p->mac+ ", "+ p->L2+ ", "+ p->vlan+ "]\n");
          return true;
      } else {
          myComment("FAILED TO insert history record ["+ p->mac+ ", "+ p->L2+ ", "+ p->vlan+ "]\n");
          return false;
      }
  }

  polling_record hP;
  hP.mac = p->mac;
  hP.vlan = p->vlan;
  hP.L2 = p->L2;

  if(!get_last_history(p->mac, &hP)) {
      myComment("PROGRAMMING ERROR: archive_polling("+p->mac+", "+p->L2+", "+p->vlan+")\nDefined in History, but failed to get last history record.\n");
      return false;
  }

  if(*p != hP) // compares mac, ifName, L2_ip_addr, vlan, and IP List.
  {
      if(insert_history(p)) {
          if(DEBUG) cout << "\tarchive_polling(): inserted history() OK\n";
          return true;
      }
      cerr << "\tERROR: archive_polling(): insert_history(): UNable to insert history record: BAD\n";
      return false;
  }
  if(DEBUG) cout << "\tarchive_polling() hP == *p \n";
  // at this time the historical polling records are the same

  fmt f;
  if(!update_history_time( f.to_string(hP.id), p->dt2)) {
      if(DEBUG) cout << "\tUNable to update history record time -- returning FALSE --\n";
      return false;
  }
  if(DEBUG) cout << "\tarchive_polling(): OK\n";
  return true;
}

//----------------------------------------------------------------------
bool delete_from_polling(string mac)
{
  if(pq->pq_exec("delete from polling where mac='" + mac + "'"))  {
      if(DEBUG) cout << "\tdelete_from_polling(" << mac << "): OK\n";
      return true;
  }
  if(DEBUG) cout << "\nERROR: delete_from_polling(" << mac << "): Returning -- FALSE --\n";
  return false;
}


//------------------------------------------------------------
void add_to_scan_queue(string mac, string ip, string last_dt)
{
  if(DEBUG) cout << "add_to_scan_queue()\n";

  if( pq->pq_count("select count(*) from cyber_scan where mac='" + mac + "'"))
  {
      string myS("update cyber_scan set ip1='" + ip + "', status='PENDING', "
                 "dt=current_timestamp where mac='" + mac + "'");

      if(pq->pq_exec(myS) == false) {
          if(!SILENT) cout << "\nERROR: add_to_scan_queue() update failed;\n\t" << myS << endl;
          return;
      }
      if(DEBUG) cout << "\tupdated cyber_scan record: " << myS << endl;
      log_record(ip, "SCAN", "updated scan record status to 'PENDING'", mac, last_dt);
  }

  else  // mac not in scan table
  {
      string myS("insert into cyber_scan (mac, ip1, dt, status) values ('" + mac + "', '" 
                 + ip + "', current_timestamp, 'PENDING')");
      if(pq->pq_exec(myS) == false) {
          if(!SILENT) cout << "\nERROR: add_to_scan_queue() insert failed;\n\t" << myS << endl;
          return;
      }
      if(DEBUG) cout << "\tinserted cyber_scan record: " << myS << endl;
      log_record(ip, "SCAN", "INSERTED scan record with status 'PENDING'", mac, last_dt);
  }
  if(DEBUG) cout << "\tadd_to_scan_queue():: OK\n";
}


//----------------------------------------------------------------------
void update_polling(vector<polling_record *> *P)
{
  if(DEBUG) cout << "update_polling() begins\n";
  if(P==0 || P->size() == 0) { 
      if(!SILENT) cout << "update_polling(P==NULL or empty)\n"; 
      return; 
  }
  fmt f;

  // for each polling record in list P ...
  for(vector<polling_record *>::iterator iter=P->begin(); iter != P->end(); ++iter) 
  {
      // Polling record relates to Bridge data.  IP addresses are **not** relevant.
      // But the polling_record holds a list of IP addresses obtained from ARP.
      // When add_to_polling, the ARP data is considered, and ip addresses are manipulated.  pR->ips

      polling_record *pR = *iter;
      pR->L2 = f.fmt_ip(pR->L2);

      string mymac = f.fmt_mac(pR->mac);

      if(mymac.length() > 0) 
      {
          pR->mac=mymac;
          polling_record last_polled;

          if(!get_polling_record(pR->mac, &last_polled)) {
              add_to_polling(pR);
              continue;
          }

          if(*pR != last_polled)  // Also looks at the IP list, ips
          {
              // then put found polling records into history, 
              // remove from polling and add new record to polling
              if(archive_polling(&last_polled)) // put into polling history
              {
                  if(!delete_from_polling(pR->mac)) { // remove from polling
                      if(!SILENT) cout << "Unable to delete from polling: " << pR->mac << endl;
                  }
                  else {
                      add_to_polling(pR); // add new one to polling
                  }
              }
          }
          else update_polling_time(pR->mac); // update timestamp on polling record
      }
      else if(!SILENT) cout << "update_polling(" << pR->L2 << "," << pR->L3 << "):: failed to format mac: " << pR->mac << "\n";
  }
}
