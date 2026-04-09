pub mod wildon {
    pub mod auth {
        pub mod v1 {
            tonic::include_proto!("wildon.auth.v1");
        }
    }

    pub mod public {
        pub mod v1 {
            tonic::include_proto!("wildon.public.v1");
        }
    }

    pub mod core {
        pub mod v1 {
            tonic::include_proto!("wildon.core.v1");
        }
    }

    pub mod storage {
        pub mod v1 {
            tonic::include_proto!("wildon.storage.v1");
        }
    }

    pub mod export {
        pub mod v1 {
            tonic::include_proto!("wildon.export.v1");
        }
    }

    pub mod logs {
        pub mod v1 {
            tonic::include_proto!("wildon.logs.v1");
        }
    }

    pub mod users {
        pub mod v1 {
            tonic::include_proto!("wildon.users.v1");
        }
    }

    pub mod api_clients {
        pub mod v1 {
            tonic::include_proto!("wildon.api_clients.v1");
        }
    }

    pub mod billing {
        pub mod v1 {
            tonic::include_proto!("wildon.billing.v1");
        }
    }

    pub mod auth_context {
        pub mod v1 {
            tonic::include_proto!("wildon.auth_context.v1");
        }
    }

    pub mod common {
        pub mod v1 {
            tonic::include_proto!("wildon.common.v1");
        }
    }
}
