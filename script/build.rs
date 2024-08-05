use sp1_helper::{build_program_with_args, BuildArgs};

fn main() {
    println!("Building program...");
    build_program_with_args(
        "../program",
        BuildArgs {
            docker: true,
            ..Default::default()
        },
    );
    println!("Program built successfully!");
}
