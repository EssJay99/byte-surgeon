use bytesurgeon_core::Result;
use tracing::{info, debug};
use std::net::TcpStream;
use std::time::Duration;

pub struct NetworkScanner {
    timeout: Duration,
    ports: Vec<u16>,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            ports: vec![22, 80, 443, 445, 2049, 548, 8080],
        }
    }

    pub fn scan_subnet(&self, subnet: &str) -> Result<Vec<String>> {
        info!("Scanning subnet: {}", subnet);
        
        let mut hosts = Vec::new();

        let base_ip: Vec<&str> = subnet.split('.').collect();
        if base_ip.len() != 4 {
            return Err(bytesurgeon_core::Error::InvalidDevice("Invalid subnet format".to_string()));
        }

        for i in 1..255 {
            let ip = format!("{}.{}.{}.{}", base_ip[0], base_ip[1], base_ip[2], i);
            
            if self.is_host_alive(&ip) {
                debug!("Host alive: {}", ip);
                hosts.push(ip);
            }
        }

        info!("Found {} active hosts", hosts.len());
        Ok(hosts)
    }

    pub fn is_host_alive(&self, ip: &str) -> bool {
        for port in &self.ports {
            let addr = format!("{}:{}", ip, port);
            if TcpStream::connect_timeout(&addr.parse().unwrap(), self.timeout).is_ok() {
                return true;
            }
        }
        false
    }

    pub fn scan_port(&self, ip: &str, port: u16) -> Result<bool> {
        let addr = format!("{}:{}", ip, port);
        match TcpStream::connect_timeout(&addr.parse()?, self.timeout) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_scanner_creation() {
        let scanner = NetworkScanner::new();
        assert!(!scanner.ports.is_empty());
        assert_eq!(scanner.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_network_scanner_default() {
        let scanner = NetworkScanner::default();
        assert!(!scanner.ports.is_empty());
    }

    #[test]
    fn test_invalid_subnet_returns_error() {
        let scanner = NetworkScanner::new();
        let result = scanner.scan_subnet("not.a.valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_subnet_too_few_octets() {
        let scanner = NetworkScanner::new();
        let result = scanner.scan_subnet("192.168");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_host_alive_unreachable() {
        let scanner = NetworkScanner::new();
        let alive = scanner.is_host_alive("192.0.2.1");
        assert!(!alive);
    }

    #[test]
    fn test_scan_port_unreachable() {
        let scanner = NetworkScanner::new();
        let result = scanner.scan_port("192.0.2.1", 9999);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
