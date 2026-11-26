use std::fs::File;
use std::net::TcpStream;
use std::process::Command;

use super::{Answer, DESCRIPTORS, refused, reply, serve};

const CHILD: &str = "KESTRIKE_AWS_DESCRIPTOR_CHILD";

/// A soft descriptor limit lower than `DESCRIPTORS / 2`.
const LIMIT: usize = 256;

/// The child process confines the lower descriptor limit to this test.
#[test]
fn a_descriptor_limit_below_the_presized_table_builds_a_server() {
    if std::env::var_os(CHILD).is_some() {
        let held: Vec<_> = (0..DESCRIPTORS / 2)
            .map(|_| File::open("/dev/null"))
            .collect();
        assert!(held.iter().any(Result::is_err));
        drop(held);
        assert_eq!(refused().port(), 1);
        let server = serve(|_| Answer::Reply(reply("200 OK", b"")));
        TcpStream::connect(server.address).unwrap();
        return;
    }
    let output = Command::new("sh")
        .args(["-c", &format!("ulimit -Sn {LIMIT} && exec \"$0\" \"$@\"")])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "loopback::tests::a_descriptor_limit_below_the_presized_table_builds_a_server",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
}
