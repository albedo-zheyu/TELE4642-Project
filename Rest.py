import json
import logging

# from ryu.app import simple_switch_13
from Switch import SimpleSwitch13
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub

simple_switch_instance_name = 'simple_switch_api_app'

class SimpleSwitchRest13(SimpleSwitch13):

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_instance_name : self})
        self.lock = hub.Event()
        self.flows = []

    def send_flow_request(self, datapath):
        self.logger.debug('send flow request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY, ofproto.OFPG_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
    	msg = ev.msg
    	flows = []
    	for stat in ev.msg.body:
    		flows.append('table_id=%s '
		                 'duration_sec=%d duration_nsec=%d '
		                 'priority=%d '
		                 'idle_timeout=%d hard_timeout=%d flags=0x%04x '
		                 'cookie=%d packet_count=%d byte_count=%d '
		                 'match=%s instructions=%s' %
		                 (stat.table_id,
		                  stat.duration_sec, stat.duration_nsec,
		                  stat.priority,
		                  stat.idle_timeout, stat.hard_timeout, stat.flags,
		                  stat.cookie, stat.packet_count, stat.byte_count,
		                  stat.match, stat.instructions))
    	self.logger.debug('FlowStats: %s', flows)
    	self.flows = flows
    	self.lock.set()


class SimpleSwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(SimpleSwitchController, self).__init__(req, link, data, **config)
		self.simpl_switch_spp = data[simple_switch_instance_name]

	@route('simpleswitch', '/mactable/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_mac_table(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		if dpid not in simple_switch.mac_to_port:
			return Response(status=404)

		mac_table = simple_switch.mac_to_port.get(dpid, {})
		body = json.dumps(mac_table, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)

	@route('simpleswitch', '/bandwidth/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_bandwidth_table(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		if dpid not in simple_switch.mac_to_port:
			return Response(status=404)

		bandwidth = {}
		bandwidth['Requested'] = simple_switch.rate_request.get(dpid, {})
		bandwidth['Allocated'] = simple_switch.rate_allocated.get(dpid, {})
		bandwidth['Used'] = simple_switch.rate_used.get(dpid, {})
		body = json.dumps(bandwidth, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)

	@route('simpleswitch', '/flows/{dpid}' , methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
	def list_flows(self, req, **kwargs):

		simple_switch = self.simpl_switch_spp
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
		dp = simple_switch.datapaths[dpid]
		simple_switch.send_flow_request(dp)
		simple_switch.lock.wait()
		body = json.dumps(simple_switch.flows, indent=4, sort_keys=True)
		return Response(content_type='application/json', body=body)



