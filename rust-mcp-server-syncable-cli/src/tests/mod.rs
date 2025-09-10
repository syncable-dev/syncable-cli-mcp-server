Cargo.toml:
[dev-dependencies]
tokio-test = "0.4"

src/tests/mod.rs:
mod handler_tests;

src/tests/handler_tests.rs:
#[cfg(test)]
mod tests {
    use tokio_test::block_on;

    #[test]
    fn hello_world() {
        block_on(async {
            assert_eq!(1 + 1, 2);
        });
    }
}