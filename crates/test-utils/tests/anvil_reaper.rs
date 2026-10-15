//! `TestAnvil` must not outlive the process that spawned it, even when that process is killed
//! before destructors run.

use std::{
    env,
    io::{BufRead as _, BufReader},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use world_id_test_utils::anvil::TestAnvil;

const CHILD_ENV: &str = "WORLD_ID_TEST_ANVIL_REAPER_CHILD";
const PID_PREFIX: &str = "anvil-pid=";

/// Does nothing unless re-run by `anvil_exits_when_spawning_process_is_killed`.
#[test]
fn spawn_anvil_and_wait_to_be_killed() {
    if env::var_os(CHILD_ENV).is_none() {
        return;
    }

    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    println!("{PID_PREFIX}{}", anvil.instance.child().id());
    thread::sleep(Duration::from_secs(300));
}

#[test]
fn anvil_exits_when_spawning_process_is_killed() {
    let mut child = Command::new(env::current_exe().expect("failed to locate test binary"))
        .args([
            "spawn_anvil_and_wait_to_be_killed",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to re-run test binary");

    let stdout = BufReader::new(child.stdout.take().expect("child stdout is piped"));
    let anvil_pid = stdout
        .lines()
        .map_while(Result::ok)
        .find_map(|line| line.strip_prefix(PID_PREFIX).map(str::to_owned))
        .expect("child exited before reporting the anvil PID");

    // SIGKILL, so no destructor runs in the child.
    child.kill().expect("failed to kill child");
    child.wait().expect("failed to wait for child");

    let deadline = Instant::now() + Duration::from_secs(10);
    while is_running(&anvil_pid) {
        if Instant::now() > deadline {
            let _ = Command::new("kill").args(["-9", &anvil_pid]).status();
            panic!("anvil (pid {anvil_pid}) outlived the killed test process");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// A killed process is either gone or a zombie until its new parent reaps it.
fn is_running(pid: &str) -> bool {
    let output = Command::new("ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("failed to run ps");
    let stat = String::from_utf8_lossy(&output.stdout);
    output.status.success() && !stat.trim_start().starts_with('Z')
}
