# This script is just a simple example I'm using to write documentation
# on how to create a Bro package along with btests

module HowTo;

export {
	redef enum Log::ID += {LOG};

	type zeek_info: record {
		ts:		time &log;
		uid:		string &log;
		id_orig_h:	addr &log;
		id_orig_p:	port &log;
		id_resp_h:	addr &log;
		id_resp_p:	port &log;
	};

}

global watch_zeek_addrs: set[addr] = [192.150.187.43];

event bro_init(){
	Log::create_stream(HowTo::LOG, [$columns=zeek_info, $path="zeek"]);
}

event connection_established(c: connection){

	if(c$id$resp_h in watch_zeek_addrs){

		Log::write(HowTo::LOG, [$ts=network_time(),
								$uid=c$uid,  
								$id_orig_h=c$id$orig_h,
								$id_orig_p=c$id$orig_p,
								$id_resp_h=c$id$resp_h, 
								$id_resp_p=c$id$resp_p]);

	}
}

