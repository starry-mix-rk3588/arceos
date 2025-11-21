use alloc::vec;
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    task::Context,
};

use axerrno::{AxError, AxResult, ax_bail, ax_err_type};
use axio::{Buf, BufMut};
use axpoll::{IoEvents, Pollable};
use smoltcp::{
    iface::SocketHandle,
    socket::icmp::{self as smol, Endpoint, PacketBuffer, PacketMetadata},
    wire::IpAddress,
};
use spin::RwLock;

use crate::{
    RecvFlags, RecvOptions, SERVICE, SOCKET_SET, SendOptions, Shutdown, SocketAddrEx, SocketOps,
    consts::{UDP_RX_BUF_LEN, UDP_TX_BUF_LEN},
    general::GeneralOptions,
    options::{Configurable, GetSocketOption, SetSocketOption},
    poll_interfaces,
};

pub(crate) fn new_raw_socket() -> smol::Socket<'static> {
    smol::Socket::new(
        PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 256],
            vec![0; UDP_RX_BUF_LEN],
        ),
        PacketBuffer::new(
            vec![PacketMetadata::EMPTY; 256],
            vec![0; UDP_TX_BUF_LEN],
        ),
    )
}

/// A RAW socket that provides POSIX-like APIs for ICMP.
pub struct RawSocket {
    handle: SocketHandle,
    local_addr: RwLock<Option<IpAddress>>,
    peer_addr: RwLock<Option<(IpAddress, IpAddress)>>, // (remote_addr, source_addr)
    icmp_ident: RwLock<Option<u16>>, // ICMP identifier
    bound: RwLock<bool>, // Signals whether the socket has been bound to an ICMP ident

    general: GeneralOptions,
}

impl RawSocket {
    /// Creates a new RAW socket for ICMP.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let socket = new_raw_socket();
        let handle = SOCKET_SET.add(socket);

        Self {
            handle,
            local_addr: RwLock::new(None),
            peer_addr: RwLock::new(None),
            icmp_ident: RwLock::new(None),
            bound: RwLock::new(false),

            general: GeneralOptions::new(),
        }
    }

    fn with_smol_socket<R>(&self, f: impl FnOnce(&mut smol::Socket) -> R) -> R {
        SOCKET_SET.with_socket_mut::<smol::Socket, _, _>(self.handle, f)
    }
}

impl Configurable for RawSocket {
    fn get_option_inner(&self, option: &mut GetSocketOption) -> AxResult<bool> {
        use GetSocketOption as O;

        if self.general.get_option_inner(option)? {
            return Ok(true);
        }
        match option {
            O::Ttl(ttl) => {
                self.with_smol_socket(|socket| {
                    **ttl = socket.hop_limit().unwrap_or(64);
                });
            }
            O::SendBuffer(size) => {
                **size = UDP_TX_BUF_LEN;
            }
            O::ReceiveBuffer(size) => {
                **size = UDP_RX_BUF_LEN;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn set_option_inner(&self, option: SetSocketOption) -> AxResult<bool> {
        use SetSocketOption as O;

        if self.general.set_option_inner(option)? {
            return Ok(true);
        }
        match option {
            O::Ttl(ttl) => {
                self.with_smol_socket(|socket| {
                    socket.set_hop_limit(Some(*ttl));
                });
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

impl SocketOps for RawSocket {
    fn bind(&self, local_addr: SocketAddrEx) -> AxResult {
        let local_addr = local_addr.into_ip()?;
        let mut guard = self.local_addr.write();

        if guard.is_some() {
            ax_bail!(InvalidInput, "already bound");
        }

        let local_ip = IpAddress::from(local_addr.ip());

        *guard = Some(local_ip);
        info!("RAW socket {}: bound on {}", self.handle, local_ip);
        Ok(())
    }

    fn connect(&self, remote_addr: SocketAddrEx) -> AxResult {
        let remote_addr = remote_addr.into_ip()?;
        let mut guard = self.peer_addr.write();
        
        if self.local_addr.read().is_none() {
            self.bind(SocketAddrEx::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )))?;
        }

        let remote_ip = IpAddress::from(remote_addr.ip());
        let source_ip = SERVICE.lock().get_source_address(&remote_ip);
        *guard = Some((remote_ip, source_ip));
        trace!("RAW socket {}: connected to {}", self.handle, remote_ip);
        Ok(())
    }

    fn send(&self, src: &mut impl Buf, options: SendOptions) -> AxResult<usize> {
        let (remote_addr, source_addr) = match options.to {
            Some(addr) => {
                let addr = IpAddress::from(addr.into_ip()?.ip());
                let src_addr = SERVICE.lock().get_source_address(&addr);
                (addr, src_addr)
            }
            None => {
                self.peer_addr.read()
                    .ok_or(AxError::NotConnected)?
            }
        };

        if self.local_addr.read().is_none() {
            self.bind(SocketAddrEx::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )))?;
        }

        let len = src.remaining();
        let mut temp_buf = vec![0u8; len];
        let read_len = src.read(&mut temp_buf[..])?;
        temp_buf.truncate(read_len);

        if !*self.bound.read() && temp_buf.len() >= 8 {
            if temp_buf[0] == 8 {
                let ident = u16::from_be_bytes([temp_buf[4], temp_buf[5]]);
                trace!("RAW socket: extracted ICMP ident {} from packet", ident);
                *self.icmp_ident.write() = Some(ident);
                
                self.with_smol_socket(|socket| {
                    socket.bind(Endpoint::Ident(ident)).map_err(|e| match e {
                        smol::BindError::InvalidState => ax_err_type!(InvalidInput, "already bound"),
                        smol::BindError::Unaddressable => ax_err_type!(ConnectionRefused, "unaddressable"),
                    })
                })?;
                *self.bound.write() = true;
                info!("RAW socket {}: bound to ICMP ident {}", self.handle, ident);
            }
        }

        if !*self.bound.read() {
            self.with_smol_socket(|socket| {
                socket.bind(Endpoint::Ident(0)).map_err(|e| match e {
                    smol::BindError::InvalidState => ax_err_type!(InvalidInput, "already bound"),
                    smol::BindError::Unaddressable => ax_err_type!(ConnectionRefused, "unaddressable"),
                })
            })?;
            *self.bound.write() = true;
        }

        self.general.send_poller(self).poll(|| {
            poll_interfaces();
            self.with_smol_socket(|socket| {
                if !socket.is_open() {
                    Err(ax_err_type!(NotConnected))
                } else if !socket.can_send() {
                    Err(AxError::WouldBlock)
                } else {
                    let buf = socket.send(temp_buf.len(), remote_addr).map_err(|e| match e {
                        smol::SendError::BufferFull => AxError::WouldBlock,
                        smol::SendError::Unaddressable => {
                            ax_err_type!(ConnectionRefused, "unaddressable")
                        }
                    })?;
                    buf.copy_from_slice(&temp_buf);
                    
                    *self.peer_addr.write() = Some((remote_addr, source_addr));
                    
                    Ok(temp_buf.len())
                }
            })
        })
    }

    fn recv(&self, dst: &mut impl BufMut, options: RecvOptions) -> AxResult<usize> {
        if self.local_addr.read().is_none() {
            ax_bail!(NotConnected);
        }

        trace!("RAW socket recv: checking for data...");
        self.general.recv_poller(self).poll(|| {
            poll_interfaces();
            self.with_smol_socket(|socket| {
                trace!("RAW socket recv: is_open={}, can_recv={}", socket.is_open(), socket.can_recv());
                if !socket.is_open() {
                    Err(ax_err_type!(NotConnected))
                } else if !socket.can_recv() {
                    Err(AxError::WouldBlock)
                } else {
                    trace!("RAW socket recv: attempting to receive...");
                    let result = socket.recv();
                    match result {
                        Ok((payload, remote_addr)) => {
                            trace!("RAW socket recv: received {} bytes from {}", payload.len(), remote_addr);
                            
                            if payload.len() < 8 {
                                warn!("RAW socket recv: payload too short: {} bytes", payload.len());
                                return Err(AxError::WouldBlock);
                            }
                            
                            // Check if it's an Echo Reply (type=0, code=0)
                            if payload[0] != 0 || payload[1] != 0 {
                                warn!("RAW socket recv: not an Echo Reply: type={}, code={}", payload[0], payload[1]);
                                return Err(AxError::WouldBlock);
                            }
                            
                            let ident = u16::from_be_bytes([payload[4], payload[5]]);
                            let seq = u16::from_be_bytes([payload[6], payload[7]]);
                            trace!("RAW socket recv: ICMP Echo Reply - ident={}, seq={}", ident, seq);
                            
                            // trace: Verify checksum
                            let read = dst.write(payload)?;
                            if read < payload.len() {
                                warn!("RAW message truncated: {} -> {} bytes", payload.len(), read);
                            }

                            Ok((if options.flags.contains(RecvFlags::TRUNCATE) {
                                payload.len()
                            } else {
                                read
                            }, remote_addr))
                        }
                        Err(smol::RecvError::Exhausted) => {
                            trace!("RAW socket recv: no data available (Exhausted)");
                            Err(AxError::WouldBlock)
                        }
                        Err(smol::RecvError::Truncated) => {
                            warn!("RAW socket recv: packet truncated");
                            Err(AxError::WouldBlock)
                        }
                    }
                }
            })
        }).map(|(size, remote_addr)| {
            if let Some(from) = options.from {
                *from = SocketAddrEx::Ip(SocketAddr::new(
                    remote_addr.into(),
                    0,
                ));
            }
            size
        })
    }

    fn local_addr(&self) -> AxResult<SocketAddrEx> {
        match self.local_addr.try_read() {
            Some(addr) => addr
                .map(|ip| SocketAddr::new(ip.into(), 0))
                .map(SocketAddrEx::Ip)
                .ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    fn peer_addr(&self) -> AxResult<SocketAddrEx> {
        match self.peer_addr.try_read() {
            Some(addr) => addr
                .map(|(ip, _)| SocketAddr::new(ip.into(), 0))
                .map(SocketAddrEx::Ip)
                .ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    fn shutdown(&self, _how: Shutdown) -> AxResult {
        poll_interfaces();

        trace!("RAW socket {}: shutting down", self.handle);
        // ICMP socket 会在 drop 时自动清理，不需要显式调用 close
        Ok(())
    }
}

impl Pollable for RawSocket {
    fn poll(&self) -> IoEvents {
        poll_interfaces();
        if self.local_addr.read().is_none() {
            return IoEvents::empty();
        }

        let mut events = IoEvents::empty();
        self.with_smol_socket(|socket| {
            events.set(IoEvents::IN, socket.can_recv());
            events.set(IoEvents::OUT, socket.can_send());
        });
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::OUT) {
            self.general.register_waker(context.waker());
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        self.shutdown(Shutdown::Both).ok();
        SOCKET_SET.remove(self.handle);
    }
}
