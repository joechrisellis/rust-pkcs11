extern crate bindgen;

use std::env;
use std::env::consts;
use std::path::{Path, PathBuf};

fn main() {
    let include_dir = env::var("PKCS11_INCLUDE_DIR").unwrap_or(String::from("./vendor"));
    println!("cargo:include={}", include_dir);

    let lib_dir = env::var_os("PKCS11_LIB_DIR").unwrap_or_else(|| {
        panic!("PKCS11_LIB_DIR environment variable is not specified.");
    });

    let lib_dir = Path::new(&lib_dir);
    let dylib_name = format!("{}pkcs11{}", consts::DLL_PREFIX, consts::DLL_SUFFIX);
    if lib_dir.join(dylib_name).exists()
        || lib_dir.join("libpkcs11.a").exists()
        || lib_dir.join("pkcs11.lib").exists()
    {
        // Tell cargo to tell rustc to link to the system pkcs11 lib.
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=pkcs11");
    }

    // Tell cargo to invalidate the build whenever the header changes.
    println!("cargo:rerun-if-changed=vendor/pkcs11.h");

    // Generate bindings.
    let bindings = bindgen::Builder::default()
        .header("vendor/pkcs11.h")
        .dynamic_library_name("Pkcs11")
        // The PKCS11 library works in a slightly different way to most shared libraries. We have
        // to call `C_GetFunctionList`, which returns a list of pointers to the _actual_ library
        // functions. This is the only function we need to create a binding for.
        .whitelist_function("C_GetFunctionList")
        // This is needed because no types will be generated if `whitelist_function` is used.
        // Unsure if this is a bug.
        .whitelist_type("*")
        // Derive the `Debug` trait for the generated structs where possible.
        .derive_debug(true)
        // Derive the `Default` trait for the generated structs where possible.
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/pkcs11_bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11_bindings.rs"))
        .expect("Couldn't write bindings!");
}
