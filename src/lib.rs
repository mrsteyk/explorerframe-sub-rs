use std::{
    ffi::{c_void, CStr},
    fmt::{Display, Write},
};

use detour::static_detour;
use skidscan::signature;
use winapi::{
    shared::{
        minwindef::{DWORD, HMODULE},
        ntdef::BOOLEAN,
    },
    um::{
        libloaderapi::DisableThreadLibraryCalls,
        shellapi::ShellExecuteA,
        winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        winuser::{MessageBoxA, MB_ICONERROR, MB_OK},
    },
};

static_detour! {
    static CExplorerTask_InternalResumeRT: extern "fastcall" fn(*mut c_void) -> u64;
}

#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GUID {
    pub data1: u32,

    pub data2: u16,
    pub data3: u16,
    pub data4: u16,

    pub data5: [u8; 6],
}

impl Display for GUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:08X}", self.data1))?;
        f.write_char('-')?;

        f.write_fmt(format_args!("{:04X}", self.data2))?;
        f.write_char('-')?;
        f.write_fmt(format_args!("{:04X}", self.data3))?;
        f.write_char('-')?;
        f.write_fmt(format_args!("{:04X}", self.data4))?;
        f.write_char('-')?;

        f.write_fmt(format_args!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data5[0],
            self.data5[1],
            self.data5[2],
            self.data5[3],
            self.data5[4],
            self.data5[5],
        ))?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Argument {
    Guid(GUID),
    DiskString(String), // Disk stuff...

    String(String), // Path stuff...
}

// We should ignore this GUID?
const CLSID_QUICK_START: GUID = GUID {
    data1: 0x679f85cb,
    data2: 0x0220,
    data3: 0x4080,
    data4: 0xb29b,
    data5: [0x55, 0x40, 0xcc, 0x05, 0xaa, 0xb6],
};

// Makes an appearance when we do `C:\` for example
const CLSID_THIS_PC: GUID = GUID {
    data1: 0x20D04FE0,
    data2: 0x3AEA,
    data3: 0x1069,
    data4: 0xA2D8,
    data5: [0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D],
};

fn il_get_size(ptr: *const u8) -> (usize, usize) {
    if unsafe { ptr.cast::<u16>().read() } != 2 {
        let mut ret = 0;
        let mut cnt = 0;
        let mut ptr = ptr;
        loop {
            let size = unsafe { ptr.cast::<u16>().read() };
            if size == 0 {
                break;
            }
            ret += size as usize;
            ptr = unsafe { ptr.add(size as usize) };
            cnt += 1;
        }
        (ret, cnt)
    } else {
        (2, 1)
    }
}

extern "fastcall" fn hook(task: *mut c_void) -> u64 {
    // parse arguments...
    let data = unsafe { task.cast::<u8>().add(0x48).cast::<*mut u8>().read() };
    let args = if data.is_null() {
        String::new()
    } else {
        let item_id_list = unsafe { data.cast::<u8>().add(0x28).cast::<*mut u8>().read() };
        let (list_size, list_len) = il_get_size(item_id_list);
        let mut args = Vec::with_capacity(list_len as usize);
        if list_size > 2 {
            let mut ptr = item_id_list;
            loop {
                if unsafe { ptr.cast::<u16>().read() } == 0 {
                    break;
                }
                let t = unsafe { ptr.add(2).read() };
                match t {
                    // makes rust-analyzer not bitch about call being unsafe while rustc compiles the code just fine
                    0x1F => unsafe {
                        // GUID start... used by trash bin?
                        // it has a weird byte before the actual GUID
                        let guid = ptr.add(4).cast::<GUID>().read();
                        if (guid != CLSID_QUICK_START) && (guid != CLSID_THIS_PC) {
                            return CExplorerTask_InternalResumeRT.call(task);
                        }
                        ptr = ptr.add(ptr.cast::<u16>().read() as usize);
                    },
                    0x2E => {
                        // GUID
                        // it has a weird byte before the actual GUID
                        let guid = unsafe { ptr.add(4).cast::<GUID>().read() };
                        if (guid != CLSID_QUICK_START) && (guid != CLSID_THIS_PC) {
                            args.push(Argument::Guid(guid));
                        }
                        ptr = unsafe { ptr.add(ptr.cast::<u16>().read() as usize) };
                    }
                    0x2F => {
                        let disk_str = unsafe {
                            CStr::from_ptr(ptr.add(3).cast())
                                .to_str()
                                .unwrap_or("")
                                .to_owned()
                        };
                        args.push(Argument::DiskString(disk_str));
                        ptr = unsafe { ptr.add(ptr.cast::<u16>().read() as usize) };
                    }
                    0x31 => {
                        let str = unsafe {
                            CStr::from_ptr(ptr.add(0xE).cast())
                                .to_str()
                                .unwrap_or("")
                                .to_owned()
                        };
                        args.push(Argument::String(str));
                        ptr = unsafe { ptr.add(ptr.cast::<u16>().read() as usize) };
                    }
                    t => unsafe {
                        MessageBoxA(
                            std::ptr::null_mut(),
                            format!("Unknown type: 0x{:02X}\0", t).as_ptr() as *const _,
                            "Error\0".as_ptr() as *const _,
                            MB_OK | MB_ICONERROR,
                        );
                        return 0;
                    },
                }
            }
            if !args.is_empty() {
                // TODO: figure out an efficient way
                let mut str = match &args[0] {
                    Argument::Guid(g) => format!("shell:::{{{}}}", g),
                    Argument::DiskString(d) => d.clone(),
                    a => unsafe {
                        MessageBoxA(
                            std::ptr::null_mut(),
                            format!("First type is: {:?}\0", a).as_ptr() as *const _,
                            "Error\0".as_ptr() as *const _,
                            MB_OK | MB_ICONERROR,
                        );
                        return 0;
                    },
                };
                for i in args.iter().skip(1) {
                    match i {
                        Argument::String(p) => {
                            str += p.as_str();
                            str.push('\\');
                        }
                        a => unsafe {
                            MessageBoxA(
                                std::ptr::null_mut(),
                                format!("Non-First type is: {:?}\0", a).as_ptr() as *const _,
                                "Error\0".as_ptr() as *const _,
                                MB_OK | MB_ICONERROR,
                            );
                            return 0;
                        },
                    }
                }
                str.push('\0');
                str
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    };
    // Launch Files v2 here...
    unsafe {
        ShellExecuteA(
            std::ptr::null_mut(),
            std::ptr::null(),
            "shell:appsFolder\\49306atecsolution.FilesUWP_et10x9a9vyk8t!App\0".as_ptr() as *const _,
            if args.is_empty() {
                std::ptr::null()
            } else {
                args.as_ptr() as *const _
            },
            std::ptr::null(),
            0,
        );
    }
    0
}

#[no_mangle]
unsafe extern "system" fn DllMain(
    hinst_dll: HMODULE,
    fdw_reason: DWORD,
    _: *mut c_void,
) -> BOOLEAN {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Init
            DisableThreadLibraryCalls(hinst_dll);
            let sig = signature!("40 53 48 83 EC 20 48 8B D9 48 8B 49 48 E8");
            let addr: *mut u8 = match sig.scan_module("ExplorerFrame.dll") {
                Ok(addr) => addr,
                Err(err) => {
                    MessageBoxA(
                        std::ptr::null_mut(),
                        format!("SigScan returned: {:?}\0", err).as_ptr() as *const _,
                        "Error\0".as_ptr() as *const _,
                        MB_OK | MB_ICONERROR,
                    );
                    return 0;
                }
            };
            #[allow(clippy::redundant_closure)]
            if let Err(err) = CExplorerTask_InternalResumeRT
                .initialize(std::mem::transmute::<_, _>(addr), |f| hook(f))
            {
                MessageBoxA(
                    std::ptr::null_mut(),
                    format!("Initialise hook returned: {:?}\0", err).as_ptr() as *const _,
                    "Error\0".as_ptr() as *const _,
                    MB_OK | MB_ICONERROR,
                );
                return 0;
            }
            if let Err(err) = CExplorerTask_InternalResumeRT.enable() {
                MessageBoxA(
                    std::ptr::null_mut(),
                    format!("Enable hook returned: {:?}\0", err).as_ptr() as *const _,
                    "Error\0".as_ptr() as *const _,
                    MB_OK | MB_ICONERROR,
                );
                return 0;
            }
            1
        }
        DLL_PROCESS_DETACH => {
            // Deinit
            let _ = CExplorerTask_InternalResumeRT.disable();
            1
        }
        _ => 0, // it do not matter to us doe ngl
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(std::mem::size_of::<crate::GUID>(), 0x10);
    }

    #[test]
    fn guid_format() {
        assert_eq!(
            format!(
                "{}",
                crate::GUID {
                    data1: 0xB4BFCC3A,
                    data2: 0xDB2C,
                    data3: 0x424C,
                    data4: 0xB029,
                    data5: [0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41],
                }
            )
            .as_str(),
            "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"
        );
    }
}
