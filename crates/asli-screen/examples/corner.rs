//! Prints where a 392 by 148 window would go, 16 pixels in from the bottom right of the usable
//! screen: `cargo run -p asli-screen --example corner`.

fn main() {
    println!("{:?}", asli_screen::bottom_right(392.0, 148.0, 16.0));
}
