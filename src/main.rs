#[macro_use]
extern crate rocket;

#[cfg(test)]
mod signer;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod util;

pub use taproot_cosigner_fun::*;

#[launch]
pub fn rocket_launcher() -> _ {
    rocket::build().mount("/", routes![xpub, sign])
}
