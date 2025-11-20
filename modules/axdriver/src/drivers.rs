//! Defines types and probe methods of all supported devices.

#![allow(unused_imports, dead_code)]

use axdriver_base::DeviceType;
#[cfg(feature = "block")]
use axdriver_block::BlockDriverOps;
#[cfg(feature = "net")]
use axdriver_net::BaseDriverOps;
#[cfg(feature = "bus-pci")]
use axdriver_pci::{DeviceFunction, DeviceFunctionInfo, PciRoot};

pub use super::dummy::*;
use crate::AxDeviceEnum;
#[cfg(feature = "virtio")]
use crate::virtio::{self, VirtIoDevMeta};

use axhal::mem::{PhysAddr, VirtAddr};
use core::arch::asm;

/// Get the D-cache line size from CTR_EL0 register
#[inline]
fn get_dcache_line_size() -> usize {
    let ctr: usize;
    unsafe {
        asm!("mrs {}, ctr_el0", out(reg) ctr);
    }
    // DminLine is bits [19:16], log2 of the number of words (4 bytes)
    let dminline = (ctr >> 16) & 0xF;
    4 << dminline // Convert log2(words) to bytes
}

/// Clean (write-back) data cache by virtual address range
///
/// This operation writes modified cache lines back to memory but leaves them in the cache.
/// This is required before DMA operations that read from memory (CPU -> Device).
///
/// # Safety
/// The caller must ensure that the address range is valid and properly aligned.
#[inline]
pub unsafe fn clean_dcache_range(addr: usize, size: usize) {
    if size == 0 {
        return;
    }

    let cache_line_size = get_dcache_line_size();
    let start = addr & !(cache_line_size - 1);
    let end = (addr + size + cache_line_size - 1) & !(cache_line_size - 1);

    let mut current = start;
    while current < end {
        unsafe {
            // DC CVAC - Data Cache Clean by VA to Point of Coherency
            asm!("dc cvac, {}", in(reg) current);
        }
        current += cache_line_size;
    }

    unsafe {
        // Ensure completion and visibility
        asm!("dsb sy");
    }
}

/// Invalidate (discard) data cache by virtual address range
///
/// This operation discards cache lines, forcing subsequent reads to fetch from memory.
/// This is required after DMA operations that write to memory (Device -> CPU).
///
/// # Safety
/// The caller must ensure that the address range is valid and properly aligned.
/// Invalidating cache lines with dirty data can cause data loss.
#[inline]
pub unsafe fn invalidate_dcache_range(addr: usize, size: usize) {
    if size == 0 {
        return;
    }

    let cache_line_size = get_dcache_line_size();
    let start = addr & !(cache_line_size - 1);
    let end = (addr + size + cache_line_size - 1) & !(cache_line_size - 1);

    let mut current = start;
    while current < end {
        unsafe {
            // DC IVAC - Data Cache Invalidate by VA to Point of Coherency
            asm!("dc ivac, {}", in(reg) current);
        }
        current += cache_line_size;
    }

    unsafe {
        // Ensure completion
        asm!("dsb sy");
    }
}


pub trait DriverProbe {
    fn probe_global() -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "mmio")]
    fn probe_mmio(_mmio_base: usize, _mmio_size: usize) -> Option<AxDeviceEnum> {
        None
    }

    #[cfg(bus = "pci")]
    fn probe_pci(
        _root: &mut PciRoot,
        _bdf: DeviceFunction,
        _dev_info: &DeviceFunctionInfo,
    ) -> Option<AxDeviceEnum> {
        None
    }
}

#[cfg(net_dev = "virtio-net")]
register_net_driver!(
    <virtio::VirtIoNet as VirtIoDevMeta>::Driver,
    <virtio::VirtIoNet as VirtIoDevMeta>::Device
);

#[cfg(block_dev = "virtio-blk")]
register_block_driver!(
    <virtio::VirtIoBlk as VirtIoDevMeta>::Driver,
    <virtio::VirtIoBlk as VirtIoDevMeta>::Device
);

#[cfg(display_dev = "virtio-gpu")]
register_display_driver!(
    <virtio::VirtIoGpu as VirtIoDevMeta>::Driver,
    <virtio::VirtIoGpu as VirtIoDevMeta>::Device
);

#[cfg(input_dev = "virtio-input")]
register_input_driver!(
    <virtio::VirtIoInput as VirtIoDevMeta>::Driver,
    <virtio::VirtIoInput as VirtIoDevMeta>::Device
);

#[cfg(vsock_dev = "virtio-socket")]
register_vsock_driver!(
    <virtio::VirtIoSocket as VirtIoDevMeta>::Driver,
    <virtio::VirtIoSocket as VirtIoDevMeta>::Device
);

cfg_if::cfg_if! {
    if #[cfg(block_dev = "ramdisk")] {
        use axdriver_block::ramdisk::RamDisk;
        use axhal::mem::phys_to_virt;

        pub struct RamDiskDriver;
        register_block_driver!(RamDiskDriver, RamDisk);

        impl DriverProbe for RamDiskDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                let (start, size) = axconfig::devices::INITRD_RANGE;
                let initrd = unsafe { RamDisk::new(phys_to_virt(start.into()).into(), size) };
                Some(AxDeviceEnum::from_block(initrd))
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "sdmmc-gpt")] {
        use axdriver_block::{gpt::GptPartitionDev, sdmmc::SdMmcDriver};
        use axhal::mem::phys_to_virt;

        pub struct SdMmcGptDriver;
        register_block_driver!(SdMmcGptDriver, GptPartitionDev<SdMmcDriver>);

        impl DriverProbe for SdMmcGptDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                let root = "root".parse().unwrap();
                let sdmmc = unsafe { SdMmcDriver::new(phys_to_virt(axconfig::devices::SDMMC_PADDR.into()).into()) };
                GptPartitionDev::try_new(sdmmc, |_, part| part.name == root)
                    .ok()
                    .map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(block_dev = "bcm2835-sdhci")]{
        pub struct BcmSdhciDriver;
        register_block_driver!(BcmSdhciDriver, axdriver_block::bcm2835sdhci::SDHCIDriver);

        impl DriverProbe for BcmSdhciDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                debug!("mmc probe");
                axdriver_block::bcm2835sdhci::SDHCIDriver::try_new().ok().map(AxDeviceEnum::from_block)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "ixgbe")] {
        use crate::ixgbe::IxgbeHalImpl;
        use axhal::mem::phys_to_virt;
        pub struct IxgbeDriver;
        register_net_driver!(IxgbeDriver, axdriver_net::ixgbe::IxgbeNic<IxgbeHalImpl, 1024, 1>);
        impl DriverProbe for IxgbeDriver {
            #[cfg(bus = "pci")]
            fn probe_pci(
                    root: &mut axdriver_pci::PciRoot,
                    bdf: axdriver_pci::DeviceFunction,
                    dev_info: &axdriver_pci::DeviceFunctionInfo,
                ) -> Option<crate::AxDeviceEnum> {
                    use axdriver_net::ixgbe::{INTEL_82599, INTEL_VEND, IxgbeNic};
                    if dev_info.vendor_id == INTEL_VEND && dev_info.device_id == INTEL_82599 {
                        // Intel 10Gb Network
                        info!("ixgbe PCI device found at {:?}", bdf);

                        // Initialize the device
                        // These can be changed according to the requirments specified in the ixgbe init function.
                        const QN: u16 = 1;
                        const QS: usize = 1024;
                        let bar_info = root.bar_info(bdf, 0).unwrap();
                        match bar_info {
                            axdriver_pci::BarInfo::Memory {
                                address,
                                size,
                                ..
                            } => {
                                let ixgbe_nic = IxgbeNic::<IxgbeHalImpl, QS, QN>::init(
                                    phys_to_virt((address as usize).into()).into(),
                                    size as usize
                                )
                                .expect("failed to initialize ixgbe device");
                                return Some(AxDeviceEnum::from_net(ixgbe_nic));
                            }
                            axdriver_pci::BarInfo::IO { .. } => {
                                error!("ixgbe: BAR0 is of I/O type");
                                return None;
                            }
                        }
                    }
                    None
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "fxmac")]{
        use axalloc::{UsageKind, global_allocator};
        use axhal::mem::PAGE_SIZE_4K;

        #[crate_interface::impl_interface]
        impl axdriver_net::fxmac::KernelFunc for FXmacDriver {
            fn virt_to_phys(addr: usize) -> usize {
                axhal::mem::virt_to_phys(addr.into()).into()
            }

            fn phys_to_virt(addr: usize) -> usize {
                axhal::mem::phys_to_virt(addr.into()).into()
            }

            fn dma_alloc_coherent(pages: usize) -> (usize, usize) {
                let Ok(vaddr) = global_allocator().alloc_pages(pages, PAGE_SIZE_4K, UsageKind::Dma) else {
                    error!("failed to alloc pages");
                    return (0, 0);
                };
                let paddr = axhal::mem::virt_to_phys((vaddr).into());
                debug!("alloc pages @ vaddr={:#x}, paddr={:#x}", vaddr, paddr);
                (vaddr, paddr.as_usize())
            }

            fn dma_free_coherent(vaddr: usize, pages: usize) {
                global_allocator().dealloc_pages(vaddr, pages, UsageKind::Dma);
            }

            fn dma_request_irq(_irq: usize, _handler: fn()) {
                warn!("unimplemented dma_request_irq for fxmax");
            }
        }

        register_net_driver!(FXmacDriver, axdriver_net::fxmac::FXmacNic);

        pub struct FXmacDriver;
        impl DriverProbe for FXmacDriver {
            fn probe_global() -> Option<AxDeviceEnum> {
                info!("fxmac for phytiumpi probe global");
                axdriver_net::fxmac::FXmacNic::init(0).ok().map(AxDeviceEnum::from_net)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(net_dev = "realtek")] {
    use axalloc::global_allocator;
    use axhal::mem::PAGE_SIZE_4K;

    #[crate_interface::impl_interface]
    impl axdriver_net::realtek::KernelFunc for RealtekDriver {
        fn virt_to_phys(addr: VirtAddr) -> PhysAddr {
            axhal::mem::virt_to_phys(addr.into()).into()
        }

        fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
            axhal::mem::phys_to_virt(addr.into()).into()
        }

        fn dma_alloc_coherent(_pages: usize) -> (usize, usize) {
            todo!()
        }

        fn dma_free_coherent(_vaddr: usize, _pages: usize) {
            todo!()
        }

        fn busy_wait(duration: core::time::Duration) {
            axhal::time::busy_wait(duration);
        }

        fn clean_dcache_range(addr: usize, size: usize) {
            #[cfg(target_arch = "aarch64")]
            {
                unsafe { clean_dcache_range(addr, size); }
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                // x86 and other architectures typically have hardware cache coherency
                let _ = (addr, size);
            }
        }

        fn invalidate_dcache_range(addr: usize, size: usize) {
            #[cfg(target_arch = "aarch64")]
            {
                unsafe { invalidate_dcache_range(addr, size); }
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                // x86 and other architectures typically have hardware cache coherency
                let _ = (addr, size);
            }
        }
    }

    register_net_driver!(RealtekDriver, axdriver_net::realtek::RealtekNic);

    pub struct RealtekDriver;
    impl DriverProbe for RealtekDriver {
        #[cfg(not(bus = "pci"))]
        fn probe_global() -> Option<AxDeviceEnum> {
            info!("RK3588 realtek driver probe (polling mode)");
            const REALTEK_BASE: usize = 0x9c0100000;
            const REALTEK_SIZE: usize = 0x10000;
            const VENDOR_ID: u16 = 0x10EC; // RealTek
            const DEVICE_ID: u16 = 0x8125; // RTL8125

            let rtl8169_vaddr = axhal::mem::phys_to_virt(REALTEK_BASE.into()).as_usize();
            info!("realtek base: phys={:#x}, virt={:#x}", REALTEK_BASE, rtl8169_vaddr);

            let realtek = axdriver_net::realtek::RealtekNic::init(
                rtl8169_vaddr
            ).ok()?;
            Some(AxDeviceEnum::from_net(realtek))
        }


        // #[cfg(bus = "pci")]
        // fn probe_pci(
        //     root: &mut PciRoot,
        //     bdf: DeviceFunction,
        //     dev_info: &DeviceFunctionInfo,
        // ) -> Option<AxDeviceEnum> {
        //     // Check if this is an realtek device
        //     if !axdriver_net::realtek::is_realtek_device(dev_info.vendor_id, dev_info.device_id) {
        //         return None;
        //     }

        //     let bar_info = root.bar_info(bdf, 1).unwrap();
        //     info!("realtek: BAR0 info: {:?}", bar_info);

        //     match bar_info {
        //         axdriver_pci::BarInfo::Memory {
        //             address,
        //             size: _,
        //             ..
        //         } => {
        //             let mmio_vaddr = axhal::mem::phys_to_virt((address as usize).into()).as_usize();
        //             return axdriver_net::realtek::create_driver(dev_info.vendor_id, dev_info.device_id, mmio_vaddr, 0xea)
        //             .ok()
        //             .map(AxDeviceEnum::from_net);
        //         }
        //         axdriver_pci::BarInfo::IO { .. } => {
        //             error!("realtek: BAR0 is of I/O type");
        //             return None;
        //         }
        //     }
        // }
    }
}
}
