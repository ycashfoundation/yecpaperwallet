use libc::{c_char};
use std::ffi::{CStr, CString};
use yecpaperlib::{pdf, paper};

/**
 * Call into rust to generate a paper wallet. Returns the paper wallet in JSON form. 
 * NOTE: the returned string is owned by rust, so the caller needs to call rust_free_string with it
 * after using it to free it properly
 */ 
#[no_mangle]
pub extern fn rust_generate_wallet(is_testnet: bool, zcount: u32, tcount: u32, entropy: *const c_char) -> *mut c_char {
    let entropy_str = unsafe {
        assert!(!entropy.is_null());

        CStr::from_ptr(entropy)
    };

    let c_str = CString::new(paper::generate_wallet(is_testnet, false, zcount, tcount, entropy_str.to_bytes())).unwrap();
    return c_str.into_raw();
}

#[no_mangle]
pub extern fn rust_save_as_pdf(is_testnet: bool, json: *const c_char, file: *const c_char)-> bool {
    let json_str = unsafe {
        assert!(!json.is_null());

        CStr::from_ptr(json)
    };

    let file_str = unsafe {
        assert!(!file.is_null());

        CStr::from_ptr(file)
    };

    match pdf::save_to_pdf(is_testnet, json_str.to_str().unwrap(), file_str.to_str().unwrap()) {
        Ok(_)   => return true,
        Err(e)  => {
            eprintln!("{}", e);
            return false;
        }

    }
}

/**
 * Callers that receive string return values from other functions should call this to return the string 
 * back to rust, so it can be freed. Failure to call this function will result in a memory leak
 */ 
#[no_mangle]
pub extern fn rust_free_string(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}
