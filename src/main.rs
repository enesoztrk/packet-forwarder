use std::env;
// adapted from https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs
extern crate pnet;
use pnet::datalink::{self, NetworkInterface,Channel, MacAddr};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::udp::UdpPacket;


use std::net::{IpAddr,Ipv4Addr};

const INTERFACE_L: &str = "enp0s3";
const INTERFACE_R: &str = "vboxnet0";

const SMA_HM2_MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(239,12,255,254);

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
		if destination == SMA_HM2_MULTICAST_IP {
	        println!(
	            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}:",
	            interface_name,
	            source,
	            udp.get_source(),
	            destination,
	            udp.get_destination(),
	            udp.get_length()
	        );
	    }
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}


fn forward_igmp_packet(interface_name:&str,total_packet_len:usize,ethernet_packet:&EthernetPacket){
	
	const IPV4_MCAST_16:MacAddr=MacAddr(0x01,0x0,0x5e,0x0,0x0,0x16);
	let mut ethernet_out_buffer:Vec<u8> = vec![0;total_packet_len];
    let mut ethernet_out_packet = MutableEthernetPacket::new(&mut ethernet_out_buffer).unwrap();

	let interface_name_match = |iface: &NetworkInterface| iface.name == interface_name;
	
	let nic = datalink::interfaces().into_iter().find(interface_name_match)
		                .unwrap_or_else(||panic!("No matching right interface"));
	
	let (mut sender, _) = match pnet::datalink::channel(&nic, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

	
	let source_ip = nic
					.ips
					.iter()
					.find(|ip| ip.is_ipv4())
					.map(|ip| match ip.ip() {
						IpAddr::V4(ip) => ip,
						_ => unreachable!(),
					})
					.unwrap();
		ethernet_out_packet.set_destination(IPV4_MCAST_16);		
		ethernet_out_packet.set_source(nic.mac.unwrap());
		ethernet_out_packet.set_ethertype(EtherTypes::Ipv4);
		
		let mut Ipv4_buffer:Vec<u8> = Vec::from(ethernet_packet.payload()); 
		let mut Ipv4_packet: MutableIpv4Packet<'_>=MutableIpv4Packet::new(&mut Ipv4_buffer).unwrap();
		
		Ipv4_packet.set_source(source_ip);

		ethernet_out_packet.set_payload(Ipv4_packet.packet_mut());

		sender.send_to(ethernet_out_packet.packet(), None).unwrap().unwrap();
		println!("IGMPv3 packet is forwarded: {:#?}",ethernet_out_packet);

}



fn handle_igmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], ethernet: &EthernetPacket){

	let  total_packet_len:usize=ethernet.packet().len(); //it should be 60
	
	if interface_name == INTERFACE_L{
	
		forward_igmp_packet(INTERFACE_R,total_packet_len,ethernet);
		println!("Left interface igmpv3 data is forwarded!");
			
	}
	else if interface_name == INTERFACE_R {
		
		forward_igmp_packet(INTERFACE_L,total_packet_len,ethernet);
		println!("Right interface igmpv3 data is forwarded!");
			

	}
	else{

	}
	println!(
		"[{}]: IGMP Packet: {}:{} > {}:{}; length: {}:",
		interface_name,
		source,
		0,
		destination,
		0,
		0
	);
	
	

}



fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
	ethernet: &EthernetPacket,
) {
	
	match protocol {

		IpNextHeaderProtocols::Igmp =>{
			handle_igmp_packet(interface_name, source, destination, packet,ethernet)
		}
		_ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    
	}

}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());

	
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
			ethernet,
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
		handle_ipv4_packet(interface_name, ethernet);
    }
}

fn main() {

	env::set_var("RUST_BACKTRACE", "1");


	use pnet::datalink::Channel::Ethernet;

	let interface_l_match = |iface: &NetworkInterface| iface.name == INTERFACE_L;
	let interfaces: Vec<NetworkInterface> = datalink::interfaces();
	let interface_left = interfaces.into_iter().find(interface_l_match)
		                .unwrap_or_else(||panic!("No matching interface"));

	let (_, mut rx_left) = match datalink::channel(&interface_left, Default::default()) {
		Ok(Ethernet(tx,rx)) => (tx, rx),
		Ok(_) => panic!("unhandled channel"),
		Err(e) => panic!("error creating channel: {}", e),
	};

	let interfaces: Vec<NetworkInterface> = datalink::interfaces();
	let interface_r_match = |iface: &NetworkInterface| iface.name == INTERFACE_R;
	let interface_right = interfaces.into_iter().find(interface_r_match)
		                .unwrap_or_else(||panic!("No matching right interface"));


						let (_, mut rx_right) = match datalink::channel(&interface_right, Default::default()) {
							Ok(Ethernet(tx,rx)) => (tx, rx),
							Ok(_) => panic!("unhandled channel"),
							Err(e) => panic!("error creating channel: {}", e),
						};
	loop {
		match rx_left.next() {
			Ok(packet) => {
				handle_ethernet_frame(&interface_left, &EthernetPacket::new(packet).unwrap());
			}
			Err(e) => panic!("error receiving packet: {}", e),
		}

		match rx_right.next() {
			Ok(packet) => {
				handle_ethernet_frame(&interface_right, &EthernetPacket::new(packet).unwrap());
			}
			Err(e) => panic!("error receiving packet: {}", e),
		}
	}
}