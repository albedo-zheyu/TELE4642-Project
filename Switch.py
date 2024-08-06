import json
import os
from threading import Timer
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

path = os.path.dirname(__file__)


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.macToPort = {}
        self.srcToMeter = {}
        self.meterToSrc = {}
        self.nMeter = {}
        self.portToMeter = {}
        with open(path + '/subs.json') as dataFile:
            self.subs = json.load(dataFile)
        self.maxRate = 40000
        self.defaultRate = 2000
        self.sleep = 10
        self.rateRequest = {}
        self.rateAllocated = {}
        self.rateUsed = {}
        self.rateUsedMod = {}
        self.datapaths = {}
        self.monitorThread = hub.spawn(self.monitor)
        self.meterSpeed = {}
        self.meterPrev = {}
        self.timePrev = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switchFeaturesHandler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch()
        self.addFlow(datapath, 0, match, actions, 1)

        # add resubmit flow
        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match,
                                instructions=inst, table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def stateChangeHandler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                # Datapath's dictionaries for BW measurement
                self.meterSpeed[datapath.id] = {}
                self.meterPrev[datapath.id] = {}
                self.timePrev[datapath.id] = {}
                # Switch's dictionaries
                self.nMeter[datapath.id] = 0
                self.macToPort[datapath.id] = {}
                self.srcToMeter[datapath.id] = {}
                self.portToMeter[datapath.id] = {}
                self.meterToSrc[datapath.id] = {}
                self.rateRequest[datapath.id] = {}
                self.rateAllocated[datapath.id] = {}
                self.rateUsed[datapath.id] = {}
                self.rateUsedMod[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                # Deleting datapath's dictionaries
                del self.datapaths[datapath.id]
                del self.meterSpeed[datapath.id]
                del self.meterPrev[datapath.id]
                del self.timePrev[datapath.id]
                # Deleting switch's dictionaries
                del self.macToPort[datapath.id]
                del self.nMeter[datapath.id]
                del self.srcToMeter[datapath.id]
                del self.portToMeter[datapath.id]
                del self.meterToSrc[datapath.id]
                del self.rateRequest[datapath.id]
                del self.rateAllocated[datapath.id]
                del self.rateUsed[datapath.id]
                del self.rateUsedMod[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.requestStats(dp)
            hub.sleep(self.sleep)

    def getSpeed(self, now, pre, period):
        return 8 * ((now - pre) / (period * 1000.0))

    def requestStats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPMeterStatsRequest(datapath, 0, ofproto.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meterStatsReplyHandler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info('datapath         meter_id   kbps  ')
        self.logger.info('---------------- -------- --------')
        modifiedPorts = []
        for stat in sorted(body, key=attrgetter('meter_id')):
            if stat.meter_id in self.timePrev[dpid]:
                sleep = float(stat.duration_sec) + (stat.duration_nsec / 10.0 ** 9) - self.timePrev[dpid][stat.meter_id]
                self.meterSpeed[dpid][stat.meter_id] = self.getSpeed(stat.byte_in_count,
                                                                     self.meterPrev[dpid][stat.meter_id], sleep)
            else:
                self.meterSpeed[dpid][stat.meter_id] = 0
            self.timePrev[dpid][stat.meter_id] = float(stat.duration_sec) + (stat.duration_nsec / 10.0 ** 9)
            self.meterPrev[dpid][stat.meter_id] = stat.byte_in_count
            self.logger.info("%016x %08x %6.1f", dpid, stat.meter_id, self.meterSpeed[dpid][stat.meter_id])
            if stat.meter_id in self.meterToSrc[dpid]:
                src = self.meterToSrc[dpid][stat.meter_id]
                port = self.macToPort[dpid][src]
                self.rateUsed[dpid].setdefault(port, {})
                self.rateUsedMod[dpid].setdefault(port, {})
                self.rateUsed[dpid][port][src] = self.meterSpeed[dpid][stat.meter_id]
                if (self.rateUsed[dpid][port][src] >= int(self.rateAllocated[dpid][port][src] * 0.7)
                        and (self.rateAllocated[dpid][port][src] < self.rateRequest[dpid][port][src])):
                    if int(self.rateAllocated[dpid][port][src] * 1.5) < self.rateRequest[dpid][port][src]:
                        self.rateUsedMod[dpid][port][src] = int(self.rateAllocated[dpid][port][src] * 1.5)
                    else:
                        self.rateUsedMod[dpid][port][src] = self.rateRequest[dpid][port][src]
                    if port not in modifiedPorts:
                        modifiedPorts.append(port)
                else:
                    self.rateUsedMod[dpid][port][src] = self.rateUsed[dpid][port][src]
        for port in modifiedPorts:
            hub.spawn(self.modifyPortMeters, dpid, port)

    def modifyPortMeters(self, dpid, in_port):
        self.logger.debug('Datapath: %s modifying port %d meters', dpid, in_port)
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cmd = ofproto.OFPMC_MODIFY
        prevAllocated = self.rateAllocated[dpid].get(in_port, {})
        self.rateAllocated[dpid][in_port] = self.rateControl(dpid, in_port)
        for src in self.rateAllocated[dpid][in_port]:
            if prevAllocated.get(src, 0) != self.rateAllocated[dpid][in_port][src]:
                rate = self.rateAllocated[dpid][in_port][src]
                match = parser.OFPMatch(in_port=self.macToPort[dpid][src], eth_src=src)
                flags = datapath.ofproto.OFPMF_KBPS
                bands = [parser.OFPMeterBandDrop(rate)]
                meterMod = parser.OFPMeterMod(datapath, cmd, flags, self.srcToMeter[dpid][src], bands)
                if cmd == ofproto.OFPMC_MODIFY and self.srcToMeter[dpid][src] in self.timePrev[datapath.id]:
                    self.timePrev[datapath.id][self.srcToMeter[dpid][src]] = 0
                    self.meterPrev[datapath.id][self.srcToMeter[dpid][src]] = 0
                datapath.send_msg(meterMod)

    def addFlow(self, datapath, priority, match, actions, table, idleTo=0, bufferId=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if bufferId:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=bufferId,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table,
                                    idle_timeout=idleTo)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table,
                                    idle_timeout=idleTo)
        datapath.send_msg(mod)

    def addQos(self, datapath, priority, match, meterId, rate, idleTo=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flags = ofproto.OFPMF_KBPS
        bands = [parser.OFPMeterBandDrop(rate)]
        meterMod = parser.OFPMeterMod(datapath, ofproto.OFPMC_ADD, flags, meterId, bands)
        datapath.send_msg(meterMod)
        inst = [parser.OFPInstructionMeter(meterId), parser.OFPInstructionGotoTable(1)]
        if idleTo == 0:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, table_id=0, idle_timeout=idleTo)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst,
                                    table_id=0, idle_timeout=idleTo)
        datapath.send_msg(mod)
        self.logger.debug('QoS added')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packetInHandler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inPort = msg.match['in_port']

        # ignore local port (4294967294)
        if inPort == 0xfffffffe:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        self.rateRequest[dpid].setdefault(inPort, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, inPort)

        # search if it is from a new in_port
        if inPort not in self.portToMeter[dpid]:
            # add in_port's default meter
            self.logger.debug('adding qos to port: %s', inPort)
            self.nMeter[dpid] += 1
            self.portToMeter[dpid][inPort] = self.nMeter[dpid]
            match = parser.OFPMatch(in_port=inPort)
            # run thread to avoid performance decreasing
            t1 = Timer(0.5, self.addQos, args=[datapath, 1, match, self.nMeter[dpid], self.defaultRate])
            t1.start()

        # search if there is a rule for the src
        if src in self.subs:
            # search if there is a existing meter already
            if src not in self.srcToMeter[dpid]:
                self.nMeter[dpid] += 1
                self.srcToMeter[dpid][src] = self.nMeter[dpid]
                self.meterToSrc[dpid][self.nMeter[dpid]] = src
                t2 = Timer(0.5, self.newSub, args=[datapath, src, inPort])
                t2.start()

        # learn a mac address to avoid FLOOD next time.
        self.macToPort[dpid][src] = inPort

        if dst in self.macToPort[dpid]:
            outPort = self.macToPort[dpid][dst]
        else:
            outPort = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(outPort)]

        # install a flow to avoid packet_in next time
        if outPort != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=inPort, eth_src=src, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.addFlow(datapath, 1, match, actions, 1, idleTo=30, buffer_id=msg.buffer_id)
                return
            else:
                self.addFlow(datapath, 1, match, actions, 1, idleTo=30)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=inPort, actions=actions, data=data)

        datapath.send_msg(out)

    def newSub(self, datapath, src, inPort):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        # recalculate rate allocated to in_port
        self.rateRequest[dpid][inPort][src] = int(self.subs[src])
        prevAllocated = self.rateAllocated[dpid].get(inPort, {})
        self.rateAllocated[dpid][inPort] = self.rateControl(dpid, inPort)
        # add meter and flow
        self.logger.debug('adding qos to src: %s', src)
        rate = self.rateAllocated[dpid][inPort][src]
        match = parser.OFPMatch(in_port=inPort, eth_src=src)
        self.addQos(datapath, 2, match, self.srcToMeter[dpid][src], rate, 30)

        # modify the others in_port's meters
        for src2 in self.rateAllocated[dpid][inPort]:
            if src != src2 and prevAllocated.get(src2, 0) != self.rateAllocated[dpid][inPort][src2]:
                self.logger.debug('modifying qos to src: %s', src2)
                cmd = ofproto.OFPMC_MODIFY
                rate = self.rateAllocated[dpid][inPort][src2]
                match = parser.OFPMatch(in_port=self.macToPort[dpid][src2], eth_src=src2)
                flags = datapath.ofproto.OFPMF_KBPS
                bands = [parser.OFPMeterBandDrop(rate)]
                meterMod = parser.OFPMeterMod(datapath, cmd, flags, self.srcToMeter[dpid][src2], bands)
                if cmd == ofproto.OFPMC_MODIFY and self.srcToMeter[dpid][src2] in self.timePrev[datapath.id]:
                    self.timePrev[datapath.id][self.srcToMeter[dpid][src2]] = 0
                    self.meterPrev[datapath.id][self.srcToMeter[dpid][src2]] = 0
                datapath.send_msg(meterMod)

    def rateControl(self, dpid, inPort):
        bandwith = self.maxRate
        requested = self.rateRequest[dpid][inPort]
        used = self.rateUsedMod[dpid].get(inPort, {})
        allocated = {}
        totalRequested = sum(requested.values())
        totalUsed = sum(used.values())
        partOfWhole = 0
        leftOver = 0
        minRate = 2000
        kFactor = 1.5
        rFactor = 0.5
        if totalRequested < bandwith:
            allocated = requested.copy()
            leftOver = bandwith - totalRequested
        else:
            requestedMod = requested.copy()
            defaultRate = []
            for src in requested:
                tmp = int((used.get(src, requested[src] * rFactor / kFactor) * kFactor))
                if tmp < requested[src]:
                    requestedMod[src] = tmp
                if requestedMod[src] < minRate:
                    requestedMod[src] = minRate
                    defaultRate.append(src)
            totalRequested = sum(requestedMod.values())
            if totalRequested < bandwith:
                allocated = requestedMod
                leftOver = bandwith - totalRequested
            else:
                partOfWhole = int(bandwith / len(requestedMod))
                leftOver = bandwith % len(requestedMod)
                for src in requestedMod:
                    if partOfWhole > requestedMod[src]:
                        allocated[src] = requestedMod[src]
                        leftOver += partOfWhole - requestedMod[src]
                    else:
                        allocated[src] = partOfWhole
                while leftOver > 0 and len(defaultRate) != len(allocated):
                    stillNeed = 0
                    for src in requestedMod:
                        if (requested[src] - allocated[src]) > 0:
                            stillNeed += 1
                    if stillNeed < leftOver:
                        for src in requestedMod:
                            if requested[src] - allocated[src] > 0 and src not in defaultRate:
                                allocated[src] += 1
                                leftOver -= 1
                    else:
                        maxDiff = 0
                        tempI = ''
                        for src in requested:
                            if requested[src] - allocated[src] > maxDiff and src not in defaultRate:
                                maxDiff = requested[src] - allocated[src]
                                tempI = src
                        allocated[tempI] += 1
                        leftOver -= 1
        return allocated

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flowRemovedHandler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        src = msg.match.get('eth_src', None)
        inPort = msg.match.get('in_port', None)
        mid = self.srcToMeter[dpid][src]

        # deleting dictionaries
        del self.meterSpeed[dpid][mid]
        if mid in self.meterPrev[dpid]:
            del self.meterPrev[dpid][mid]
            del self.timePrev[dpid][mid]
        del self.meterToSrc[dpid][mid]
        del self.srcToMeter[dpid][src]
        del self.rateRequest[dpid][inPort][src]
        del self.rateAllocated[dpid][inPort][src]
        del self.rateUsed[dpid][inPort][src]
        del self.rateUsedMod[dpid][inPort][src]

        # deleting meter
        cmd = ofp.OFPMC_DELETE
        flags = dp.ofproto.OFPMF_KBPS
        bands = [parser.OFPMeterBandDrop(0)]
        meterMod = parser.OFPMeterMod(dp, cmd, flags, mid, bands)
        dp.send_msg(meterMod)
        # modifying other meters
        self.modifyPortMeters(dpid, inPort)

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
