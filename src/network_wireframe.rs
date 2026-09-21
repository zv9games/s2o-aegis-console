#![allow(dead_code)]

use winapi::um::winsock2::{
    WSADATA, WSAStartup, WSACleanup, SOCKET, INVALID_SOCKET, SOCK_RAW, socket, WSAGetLastError,
    SOCKET_ERROR, bind, setsockopt, recv, select, timeval, fd_set,
};
use winapi::shared::ws2def::{AF_INET, SOCKADDR_IN, SOCKADDR, IPPROTO_IP, IPPROTO_RAW};
use winapi::shared::ws2ipdef::IP_HDRINCL;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::sync::atomic::{AtomicBool};
use std::sync::Arc;
use std::ptr;
use std::error::Error;

mod network_interfaces {
    pub struct NetworkInterface {
        pub name: String,
        pub operational_status: String,
    }

    pub fn list_network_interfaces() -> Vec<NetworkInterface> {
        vec![NetworkInterface {
            name: "Ethernet".to_string(),
            operational_status: "Up".to_string(),
        }]
    }
}

pub fn capture_network_packets() -> Result<(), Box<dyn Error>> {
    // List network interfaces
    let interfaces = network_interfaces::list_network_interfaces();

    for interface in &interfaces {
        if interface.operational_status == "Up" {
            println!("Checking network activity on interface: {}", interface.name);

            if detect_network_activity(&interface.name) {
                println!("Network activity detected on interface: {}", interface.name);

                println!("Attempting to bind to interface: {}", interface.name);

                if let Err(e) = initialize_and_capture(&interface.name) {
                    eprintln!("Error binding to interface {}: {}", interface.name, e);
                } else {
                    println!("Successfully bound to interface: {}", interface.name);
                }
            } else {
                println!("No network activity detected on interface: {}", interface.name);
            }
        }
    }

    println!("Finished checking all active network interfaces.");
    Ok(())
}

fn detect_network_activity(_interface_name: &str) -> bool {
    // Simulate checking for network activity.
    // This should be replaced with actual logic to detect network activity.
    true // Assume network activity is always detected for demonstration purposes
}

fn initialize_and_capture(interface_name: &str) -> Result<(), Box<dyn Error>> {
    println!("Initializing Winsock...");
    let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
    if unsafe { WSAStartup(0x0202, &mut wsa_data) } != 0 {
        eprintln!("WSAStartup failed with error: {}", unsafe { WSAGetLastError() });
        return Err("WSAStartup failed".into());
    }
    println!("Winsock initialized successfully.");

    println!("Creating socket...");
    let socket: SOCKET = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_RAW as i32) };
    if socket == INVALID_SOCKET {
        eprintln!("Failed to create socket with error: {}", unsafe { WSAGetLastError() });
        unsafe { WSACleanup() };
        return Err("Failed to create socket".into());
    }
    println!("Socket created successfully.");

    println!("Setting socket options...");
    let opt_val: i32 = 1;
    if unsafe { setsockopt(socket, IPPROTO_IP as i32, IP_HDRINCL as i32, &opt_val as *const _ as *const i8, std::mem::size_of::<i32>() as i32) } == SOCKET_ERROR {
        eprintln!("Failed to set socket options with error: {}", unsafe { WSAGetLastError() });
        unsafe { WSACleanup() };
        return Err("Failed to set socket options".into());
    }
    println!("Socket options set successfully.");

    println!("Binding socket to interface {}...", interface_name);
    let addr = SOCKADDR_IN {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: unsafe { std::mem::zeroed() },
        sin_zero: [0; 8],
    };
    let result = unsafe {
        bind(socket, &addr as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32)
    };
    if result == SOCKET_ERROR {
        eprintln!("Failed to bind socket with error: {}", unsafe { WSAGetLastError() });
        unsafe { WSACleanup() };
        return Err("Failed to bind socket".into());
    }
    println!("Socket bound successfully to interface: {}", interface_name);

    let stop_signal = Arc::new(AtomicBool::new(false));

    println!("Starting packet capture...");
    let capture_result = local_capture_packets(socket, |packet| {
        println!("Packet received with length: {}", packet.len());
        if packet.len() >= 20 {
            let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            println!("Src: {}, Dest: {}", src_ip, dest_ip);
        }
    }, stop_signal);

    if capture_result.is_err() {
        eprintln!("Packet capture failed on interface {}: {}", interface_name, capture_result.err().unwrap());
    } else {
        println!("Packet capture successful on interface: {}", interface_name);
    }

    // Cleanup Winsock
    unsafe { WSACleanup() };
    println!("Winsock cleanup complete.");

    Ok(())
}

fn local_capture_packets<F>(socket: SOCKET, handle_packet: F, stop_signal: Arc<AtomicBool>) -> Result<(), Box<dyn Error>>
where
    F: Fn(&[u8]) + Send + Sync + 'static,
{
    let mut buffer = [0u8; 65535];
    let extended_timeout = Duration::from_secs(1);
    let mut readfds = unsafe { std::mem::zeroed::<fd_set>() };
    let mut timeout = timeval {
        tv_sec: 1,
        tv_usec: 0,
    };

    println!("Starting packet capture...");

    while !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
        for fd in &mut readfds.fd_array {
            *fd = 0;
        }
        readfds.fd_count = 0;
        if readfds.fd_count < 64 {
            readfds.fd_array[readfds.fd_count as usize] = socket;
            readfds.fd_count += 1;
        }

        println!("Checking for packets...");
        let select_result = unsafe { select(0, &mut readfds, ptr::null_mut(), ptr::null_mut(), &mut timeout) };
        if select_result > 0 {
            println!("Socket is ready for reading...");
            let packet_size = unsafe { recv(socket, buffer.as_mut_ptr() as *mut _, buffer.len() as i32, 0) };
            if packet_size == -1 {
                let error_code = unsafe { WSAGetLastError() };
                eprintln!("Error: Failed to capture packet. Error code: {}", error_code);
                return Err("Failed to capture packet".into());
            }

            if packet_size > 0 {
                println!("Captured packet of size: {}", packet_size);
                handle_packet(&buffer[..packet_size as usize]);
                return Ok(());
            } else {
                println!("Packet size is zero.");
            }
        } else if select_result == 0 {
            println!("No packets available to read (timeout).");
        } else {
            let error_code = unsafe { WSAGetLastError() };
            eprintln!("Error in select. Error code: {}", error_code);
            return Err("Error in select".into());
        }

        std::thread::sleep(extended_timeout);
    }

    println!("Packet capture ended.");
    Ok(())
}
