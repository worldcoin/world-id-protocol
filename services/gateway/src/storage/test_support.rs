use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};

pub(super) async fn start_redis() -> (String, ContainerAsync<Redis>) {
    let container = Redis::default()
        .with_tag("latest")
        .start()
        .await
        .expect("failed to start Redis container");
    let host = container
        .get_host()
        .await
        .expect("failed to get Redis host");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("failed to get Redis port");

    (format!("redis://{host}:{port}"), container)
}
