use std::collections::HashSet;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct LanSubnet {
    pub cidr: Ipv4Cidr,
}

#[derive(Debug, Clone)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8
}

#[derive(Debug, Error)]
pub enum IpAllocError {
    #[error("invalid pool prefix of {0}")]
    InvalidPool(u8),
    #[error("pool exhausted")]
    PoolExhausted
}

#[derive(Debug)]
pub struct LanIpAllocator {
    cidr: LanSubnet,
    next_host_offset: u32,
    allocated: HashSet<Ipv4Addr>,
}
impl LanIpAllocator {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, IpAllocError> {
        if prefix > 30 {
            return Err(IpAllocError::InvalidPool(prefix));
        }

        Ok(Self {
            cidr: LanSubnet {
                cidr: Ipv4Cidr{network, prefix},
            },
            next_host_offset: 1, // skip network address
            allocated: HashSet::new(),
        })
    }

    pub fn subnet(&self) -> LanSubnet {
        self.cidr.clone()
    }

    pub fn allocate_ip(&mut self) -> Result<Ipv4Addr, IpAllocError> {
        let network = self.cidr.cidr.network.to_bits();
        let total_size = 1u32 << (32 - self.cidr.cidr.prefix);

        // reserve broadcast too, so last usable is total_size - 2
        while self.next_host_offset < total_size - 1 {
            let ip = Ipv4Addr::from_bits(network + self.next_host_offset);
            self.next_host_offset += 1;

            if self.allocated.insert(ip) {
                return Ok(ip);
            }
        }

        Err(IpAllocError::PoolExhausted)
    }

    pub fn free_ip(&mut self, ip: Ipv4Addr) {
        if self.allocated.remove(&ip) {
            let network = self.cidr.cidr.network.to_bits();
            let total_size = 1u32 << (32 - self.cidr.cidr.prefix);
            let ip_bits = ip.to_bits();

            if ip_bits > network && ip_bits < network + total_size - 1 {
                let offset = ip_bits - network;
                self.next_host_offset = self.next_host_offset.min(offset);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IpAllocError, LanIpAllocator};
    use std::net::Ipv4Addr;

    #[test]
    fn new_rejects_prefixes_above_30() {
        let result = LanIpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 31);

        assert!(matches!(result, Err(IpAllocError::InvalidPool(31))));
    }

    #[test]
    fn subnet_returns_configured_network_and_prefix() {
        let allocator = LanIpAllocator::new(Ipv4Addr::new(10, 1, 0, 0), 24).unwrap();
        let subnet = allocator.subnet();

        assert_eq!(subnet.cidr.network, Ipv4Addr::new(10, 1, 0, 0));
        assert_eq!(subnet.cidr.prefix, 24);
    }

    #[test]
    fn allocate_ip_skips_reserved_addresses_and_exhausts_pool() {
        let mut allocator = LanIpAllocator::new(Ipv4Addr::new(192, 168, 1, 0), 30).unwrap();

        assert_eq!(allocator.allocate_ip().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(allocator.allocate_ip().unwrap(), Ipv4Addr::new(192, 168, 1, 2));
        assert!(matches!(
            allocator.allocate_ip(),
            Err(IpAllocError::PoolExhausted)
        ));
    }

    #[test]
    fn free_ip_allows_reuse_of_released_address() {
        let mut allocator = LanIpAllocator::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();

        let first = allocator.allocate_ip().unwrap();
        let second = allocator.allocate_ip().unwrap();
        let third = allocator.allocate_ip().unwrap();

        assert_eq!(first, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(second, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(third, Ipv4Addr::new(10, 0, 0, 3));

        allocator.free_ip(second);

        assert_eq!(allocator.allocate_ip().unwrap(), second);
    }
}
