--------------------------- MODULE redplane_lease ---------------------------
EXTENDS Integers, Sequences, TLC, FiniteSets
CONSTANTS NULL, SWITCHES, LEASE_PERIOD, TOTAL_PKTS

(*--algorithm lease
variables
  query = [sw \in SWITCHES |-> NULL];
  request_queue = <<>>;
  SwitchPacketQueue = [sw \in SWITCHES |-> 0]; \*\* Initially all switches do not have packets
  RemainingLeasePeriod = [sw \in SWITCHES |-> 0]; \*\* Initially all switches do not have a lease 
  owner = NULL;
  up = [sw \in SWITCHES |-> TRUE]; \*\* Initially all switches are up
  active = [sw \in SWITCHES |-> FALSE]; 
  AliveNum = Cardinality(SWITCHES);
  global_seqnum = 0;
 
define
  Exists(val) == val /= NULL
  RequestingSwitches == {sw \in SWITCHES: Exists(query[sw]) /\ query[sw].type = "request"}
end define;  
  
macro request(data) begin
  query[self] := [type |-> "request"] @@ data;
  request_queue := Append(request_queue, self);
end macro;

macro response(data) begin
  query[switch] := [type |-> "response"] @@ data;
end macro;

macro wait_for_lease_response() begin
  await query[self].type = "response";
  seqnum := query[self].last_seqnum;
  query[self] := NULL;
end macro;

macro wait_for_response() begin
  await query[self].type = "response";
  assert seqnum = query[self].last_seqnum;
  query[self] := NULL;
end macro;

macro buffer_until_expired() begin
  request_queue := Append(request_queue, switch);
end macro;

fair process statestore = "StateStore"
variable switch = NULL, q = NULL;
begin
START_STORE:
    while TRUE do
        STORE_PROCESSING:
        if request_queue /= <<>> then \* If it receives something
            switch := Head(request_queue);
            request_queue := Tail(request_queue);  
            q := query[switch];
            if q.lease_request = "new" then \* request a new lease
                if owner /= NULL then \* If someone already owns the lease
                    BUFFERING:
                    buffer_until_expired(); 
                    goto STORE_PROCESSING;
                end if;
                TRANSFER_LEASE:     
                response([last_seqnum |-> global_seqnum]); \* send a response with a last seqnum seen
                RemainingLeasePeriod[switch] := LEASE_PERIOD; \* Set a lease period
                owner := switch;
            elsif q.lease_request = "renew" then \* renew request
                RENEW_LEASE:
                global_seqnum := q.write_seq; \* update the global seqnum
                response([last_seqnum |-> global_seqnum]); \* send a response with a last seqnum seen
                RemainingLeasePeriod[switch] := LEASE_PERIOD; \* Extend a lease period  
                owner := switch;              
            end if;
        end if;
   end while;
end process;

fair process switch \in SWITCHES
variable seqnum = 0, round = 0;
begin
START_SWITCH: 
    while TRUE do
      either
        await(up[self] /\ SwitchPacketQueue[self] > 0);
        active[self] := TRUE;   
        if RemainingLeasePeriod[self] = 0 then\* If it does not have a valid lease
            NO_LEASE:
            request([lease_request |-> "new"]); \* send a request
            WAIT_LEASE_RESPONSE:
            wait_for_lease_response(); \* wait for a response
        end if;
                
        HAS_LEASE:
        seqnum := seqnum + 1;
        request([lease_request |-> "renew", write_seq |-> seqnum]); \* send a request
        WAIT_WRITE_RESPONSE:
        wait_for_response(); \* wait for a response
        active[self] := FALSE;
        SwitchPacketQueue[self] := SwitchPacketQueue[self] - 1;
      or
      SW_FAILURE:
        if AliveNum>1 /\ up[self]=TRUE then \* Switch can fail
            up[self]:=FALSE;
            AliveNum:=AliveNum-1;
        elsif up[self]=FALSE then  \* Or recovered
            up[self]:=TRUE;
            query[self] := NULL;
            AliveNum:=AliveNum+1;
        end if 
      end either;
    end while;  
end process;

fair process expirationTimer = "LeaseTimer"
begin
START_TIMER:
    while TRUE do
        await owner /= NULL; \* Wait until someone becomes an owner.
        if RemainingLeasePeriod[owner] > 0 /\ active[owner] = FALSE then 
            RemainingLeasePeriod[owner] := RemainingLeasePeriod[owner] - 1; \* Decrement the lease period
        elsif RemainingLeasePeriod[owner] = 0 then \* if it expires
            owner := NULL; 
        end if;    
    end while;    
end process;

fair process packetGen = "pktgen"
variable upSwitches = {}, sent_pkts = 0;
begin
START_PKTGEN:
    while sent_pkts < TOTAL_PKTS do
        await AliveNum > 0; 
        upSwitches := {sw \in SWITCHES: up[sw]};   
        with sw \in upSwitches do
            SwitchPacketQueue[sw] := SwitchPacketQueue[sw] + 1;  \* Inject a packet to one of alive switches. 
        end with;
        sent_pkts := sent_pkts + 1;                
    end while;    
end process;

end algorithm; *)
\* BEGIN TRANSLATION
\* Process switch at line 78 col 6 changed to switch_
VARIABLES query, request_queue, SwitchPacketQueue, RemainingLeasePeriod, 
          owner, up, active, AliveNum, global_seqnum, pc

(* define statement *)
Exists(val) == val /= NULL
RequestingSwitches == {sw \in SWITCHES: Exists(query[sw]) /\ query[sw].type = "request"}

VARIABLES switch, q, seqnum, round, upSwitches, sent_pkts

vars == << query, request_queue, SwitchPacketQueue, RemainingLeasePeriod, 
           owner, up, active, AliveNum, global_seqnum, pc, switch, q, seqnum, 
           round, upSwitches, sent_pkts >>

ProcSet == {"StateStore"} \cup (SWITCHES) \cup {"LeaseTimer"} \cup {"pktgen"}

Init == (* Global variables *)
        /\ query = [sw \in SWITCHES |-> NULL]
        /\ request_queue = <<>>
        /\ SwitchPacketQueue = [sw \in SWITCHES |-> 0]
        /\ RemainingLeasePeriod = [sw \in SWITCHES |-> 0]
        /\ owner = NULL
        /\ up = [sw \in SWITCHES |-> TRUE]
        /\ active = [sw \in SWITCHES |-> FALSE]
        /\ AliveNum = Cardinality(SWITCHES)
        /\ global_seqnum = 0
        (* Process statestore *)
        /\ switch = NULL
        /\ q = NULL
        (* Process switch_ *)
        /\ seqnum = [self \in SWITCHES |-> 0]
        /\ round = [self \in SWITCHES |-> 0]
        (* Process packetGen *)
        /\ upSwitches = {}
        /\ sent_pkts = 0
        /\ pc = [self \in ProcSet |-> CASE self = "StateStore" -> "START_STORE"
                                        [] self \in SWITCHES -> "START_SWITCH"
                                        [] self = "LeaseTimer" -> "START_TIMER"
                                        [] self = "pktgen" -> "START_PKTGEN"]

START_STORE == /\ pc["StateStore"] = "START_STORE"
               /\ pc' = [pc EXCEPT !["StateStore"] = "STORE_PROCESSING"]
               /\ UNCHANGED << query, request_queue, SwitchPacketQueue, 
                               RemainingLeasePeriod, owner, up, active, 
                               AliveNum, global_seqnum, switch, q, seqnum, 
                               round, upSwitches, sent_pkts >>

STORE_PROCESSING == /\ pc["StateStore"] = "STORE_PROCESSING"
                    /\ IF request_queue /= <<>>
                          THEN /\ switch' = Head(request_queue)
                               /\ request_queue' = Tail(request_queue)
                               /\ q' = query[switch']
                               /\ IF q'.lease_request = "new"
                                     THEN /\ IF owner /= NULL
                                                THEN /\ pc' = [pc EXCEPT !["StateStore"] = "BUFFERING"]
                                                ELSE /\ pc' = [pc EXCEPT !["StateStore"] = "TRANSFER_LEASE"]
                                     ELSE /\ IF q'.lease_request = "renew"
                                                THEN /\ pc' = [pc EXCEPT !["StateStore"] = "RENEW_LEASE"]
                                                ELSE /\ pc' = [pc EXCEPT !["StateStore"] = "START_STORE"]
                          ELSE /\ pc' = [pc EXCEPT !["StateStore"] = "START_STORE"]
                               /\ UNCHANGED << request_queue, switch, q >>
                    /\ UNCHANGED << query, SwitchPacketQueue, 
                                    RemainingLeasePeriod, owner, up, active, 
                                    AliveNum, global_seqnum, seqnum, round, 
                                    upSwitches, sent_pkts >>

TRANSFER_LEASE == /\ pc["StateStore"] = "TRANSFER_LEASE"
                  /\ query' = [query EXCEPT ![switch] = [type |-> "response"] @@ ([last_seqnum |-> global_seqnum])]
                  /\ RemainingLeasePeriod' = [RemainingLeasePeriod EXCEPT ![switch] = LEASE_PERIOD]
                  /\ owner' = switch
                  /\ pc' = [pc EXCEPT !["StateStore"] = "START_STORE"]
                  /\ UNCHANGED << request_queue, SwitchPacketQueue, up, active, 
                                  AliveNum, global_seqnum, switch, q, seqnum, 
                                  round, upSwitches, sent_pkts >>

BUFFERING == /\ pc["StateStore"] = "BUFFERING"
             /\ request_queue' = Append(request_queue, switch)
             /\ pc' = [pc EXCEPT !["StateStore"] = "STORE_PROCESSING"]
             /\ UNCHANGED << query, SwitchPacketQueue, RemainingLeasePeriod, 
                             owner, up, active, AliveNum, global_seqnum, 
                             switch, q, seqnum, round, upSwitches, sent_pkts >>

RENEW_LEASE == /\ pc["StateStore"] = "RENEW_LEASE"
               /\ global_seqnum' = q.write_seq
               /\ query' = [query EXCEPT ![switch] = [type |-> "response"] @@ ([last_seqnum |-> global_seqnum'])]
               /\ RemainingLeasePeriod' = [RemainingLeasePeriod EXCEPT ![switch] = LEASE_PERIOD]
               /\ owner' = switch
               /\ pc' = [pc EXCEPT !["StateStore"] = "START_STORE"]
               /\ UNCHANGED << request_queue, SwitchPacketQueue, up, active, 
                               AliveNum, switch, q, seqnum, round, upSwitches, 
                               sent_pkts >>

statestore == START_STORE \/ STORE_PROCESSING \/ TRANSFER_LEASE
                 \/ BUFFERING \/ RENEW_LEASE

START_SWITCH(self) == /\ pc[self] = "START_SWITCH"
                      /\ \/ /\ (up[self] /\ SwitchPacketQueue[self] > 0)
                            /\ active' = [active EXCEPT ![self] = TRUE]
                            /\ IF RemainingLeasePeriod[self] = 0
                                  THEN /\ pc' = [pc EXCEPT ![self] = "NO_LEASE"]
                                  ELSE /\ pc' = [pc EXCEPT ![self] = "HAS_LEASE"]
                         \/ /\ pc' = [pc EXCEPT ![self] = "SW_FAILURE"]
                            /\ UNCHANGED active
                      /\ UNCHANGED << query, request_queue, SwitchPacketQueue, 
                                      RemainingLeasePeriod, owner, up, 
                                      AliveNum, global_seqnum, switch, q, 
                                      seqnum, round, upSwitches, sent_pkts >>

NO_LEASE(self) == /\ pc[self] = "NO_LEASE"
                  /\ query' = [query EXCEPT ![self] = [type |-> "request"] @@ ([lease_request |-> "new"])]
                  /\ request_queue' = Append(request_queue, self)
                  /\ pc' = [pc EXCEPT ![self] = "WAIT_LEASE_RESPONSE"]
                  /\ UNCHANGED << SwitchPacketQueue, RemainingLeasePeriod, 
                                  owner, up, active, AliveNum, global_seqnum, 
                                  switch, q, seqnum, round, upSwitches, 
                                  sent_pkts >>

WAIT_LEASE_RESPONSE(self) == /\ pc[self] = "WAIT_LEASE_RESPONSE"
                             /\ query[self].type = "response"
                             /\ seqnum' = [seqnum EXCEPT ![self] = query[self].last_seqnum]
                             /\ query' = [query EXCEPT ![self] = NULL]
                             /\ pc' = [pc EXCEPT ![self] = "HAS_LEASE"]
                             /\ UNCHANGED << request_queue, SwitchPacketQueue, 
                                             RemainingLeasePeriod, owner, up, 
                                             active, AliveNum, global_seqnum, 
                                             switch, q, round, upSwitches, 
                                             sent_pkts >>

HAS_LEASE(self) == /\ pc[self] = "HAS_LEASE"
                   /\ seqnum' = [seqnum EXCEPT ![self] = seqnum[self] + 1]
                   /\ query' = [query EXCEPT ![self] = [type |-> "request"] @@ ([lease_request |-> "renew", write_seq |-> seqnum'[self]])]
                   /\ request_queue' = Append(request_queue, self)
                   /\ pc' = [pc EXCEPT ![self] = "WAIT_WRITE_RESPONSE"]
                   /\ UNCHANGED << SwitchPacketQueue, RemainingLeasePeriod, 
                                   owner, up, active, AliveNum, global_seqnum, 
                                   switch, q, round, upSwitches, sent_pkts >>

WAIT_WRITE_RESPONSE(self) == /\ pc[self] = "WAIT_WRITE_RESPONSE"
                             /\ query[self].type = "response"
                             /\ Assert(seqnum[self] = query[self].last_seqnum, 
                                       "Failure of assertion at line 39, column 3 of macro called at line 97, column 9.")
                             /\ query' = [query EXCEPT ![self] = NULL]
                             /\ active' = [active EXCEPT ![self] = FALSE]
                             /\ SwitchPacketQueue' = [SwitchPacketQueue EXCEPT ![self] = SwitchPacketQueue[self] - 1]
                             /\ pc' = [pc EXCEPT ![self] = "START_SWITCH"]
                             /\ UNCHANGED << request_queue, 
                                             RemainingLeasePeriod, owner, up, 
                                             AliveNum, global_seqnum, switch, 
                                             q, seqnum, round, upSwitches, 
                                             sent_pkts >>

SW_FAILURE(self) == /\ pc[self] = "SW_FAILURE"
                    /\ IF AliveNum>1 /\ up[self]=TRUE
                          THEN /\ up' = [up EXCEPT ![self] = FALSE]
                               /\ AliveNum' = AliveNum-1
                               /\ query' = query
                          ELSE /\ IF up[self]=FALSE
                                     THEN /\ up' = [up EXCEPT ![self] = TRUE]
                                          /\ query' = [query EXCEPT ![self] = NULL]
                                          /\ AliveNum' = AliveNum+1
                                     ELSE /\ TRUE
                                          /\ UNCHANGED << query, up, AliveNum >>
                    /\ pc' = [pc EXCEPT ![self] = "START_SWITCH"]
                    /\ UNCHANGED << request_queue, SwitchPacketQueue, 
                                    RemainingLeasePeriod, owner, active, 
                                    global_seqnum, switch, q, seqnum, round, 
                                    upSwitches, sent_pkts >>

switch_(self) == START_SWITCH(self) \/ NO_LEASE(self)
                    \/ WAIT_LEASE_RESPONSE(self) \/ HAS_LEASE(self)
                    \/ WAIT_WRITE_RESPONSE(self) \/ SW_FAILURE(self)

START_TIMER == /\ pc["LeaseTimer"] = "START_TIMER"
               /\ owner /= NULL
               /\ IF RemainingLeasePeriod[owner] > 0 /\ active[owner] = FALSE
                     THEN /\ RemainingLeasePeriod' = [RemainingLeasePeriod EXCEPT ![owner] = RemainingLeasePeriod[owner] - 1]
                          /\ owner' = owner
                     ELSE /\ IF RemainingLeasePeriod[owner] = 0
                                THEN /\ owner' = NULL
                                ELSE /\ TRUE
                                     /\ owner' = owner
                          /\ UNCHANGED RemainingLeasePeriod
               /\ pc' = [pc EXCEPT !["LeaseTimer"] = "START_TIMER"]
               /\ UNCHANGED << query, request_queue, SwitchPacketQueue, up, 
                               active, AliveNum, global_seqnum, switch, q, 
                               seqnum, round, upSwitches, sent_pkts >>

expirationTimer == START_TIMER

START_PKTGEN == /\ pc["pktgen"] = "START_PKTGEN"
                /\ IF sent_pkts < TOTAL_PKTS
                      THEN /\ AliveNum >= 1
                           /\ upSwitches' = {sw \in SWITCHES: up[sw]}
                           /\ \E sw \in upSwitches':
                                SwitchPacketQueue' = [SwitchPacketQueue EXCEPT ![sw] = SwitchPacketQueue[sw] + 1]
                           /\ sent_pkts' = sent_pkts + 1
                           /\ pc' = [pc EXCEPT !["pktgen"] = "START_PKTGEN"]
                      ELSE /\ pc' = [pc EXCEPT !["pktgen"] = "Done"]
                           /\ UNCHANGED << SwitchPacketQueue, upSwitches, 
                                           sent_pkts >>
                /\ UNCHANGED << query, request_queue, RemainingLeasePeriod, 
                                owner, up, active, AliveNum, global_seqnum, 
                                switch, q, seqnum, round >>

packetGen == START_PKTGEN

Next == statestore \/ expirationTimer \/ packetGen
           \/ (\E self \in SWITCHES: switch_(self))

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(statestore)
        /\ \A self \in SWITCHES : WF_vars(switch_(self))
        /\ WF_vars(expirationTimer)
        /\ WF_vars(packetGen)

\* END TRANSLATION

AtLeastOneAliveSwitch ==
    /\ AliveNum >= 1
    /\ \E sw \in SWITCHES: up[sw] = TRUE

SingleOwnerInvariant ==
    \A sw \in SWITCHES: 
    sw /= owner => RemainingLeasePeriod[sw] = 0

(*NextInLineFor(p) ==
  /\ request_queue /= <<>>
  /\ p = Head(request_queue)*)  

Liveness ==
    \/ \A sw \in SWITCHES:
        (query[sw] /= NULL /\ query[sw].type = "request") ~>
            owner = sw
            (*\/ NextInLineFor(sw)
            \/ \A i \in DOMAIN request_queue: request_queue[i] /= sw*)


=============================================================================
\* Modification History
\* Last modified Wed Mar 25 21:42:09 PDT 2020 by daeki
\* Created Sun Mar 22 22:22:56 PDT 2020 by daeki
