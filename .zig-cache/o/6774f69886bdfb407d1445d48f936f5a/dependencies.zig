pub const packages = struct {
    pub const @"TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V";
        pub const build_zig = @import("TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zcrypto-0.0.0-rgQAI8fbAwClmk2Me7c0fNLBtFWbukRh3ZgB2_IckfYz" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.0.0-rgQAI8fbAwClmk2Me7c0fNLBtFWbukRh3ZgB2_IckfYz";
        pub const build_zig = @import("zcrypto-0.0.0-rgQAI8fbAwClmk2Me7c0fNLBtFWbukRh3ZgB2_IckfYz");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"zqlite-0.4.0-0Cdu4lREBQAn6qz7Fwg5KDh8V7Kwc2JBEUxJjUckkP9V" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zqlite-0.4.0-0Cdu4lREBQAn6qz7Fwg5KDh8V7Kwc2JBEUxJjUckkP9V";
        pub const build_zig = @import("zqlite-0.4.0-0Cdu4lREBQAn6qz7Fwg5KDh8V7Kwc2JBEUxJjUckkP9V");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zcrypto", "zcrypto-0.0.0-rgQAI8fbAwClmk2Me7c0fNLBtFWbukRh3ZgB2_IckfYz" },
            .{ "tokioz", "TokioZ-0.0.0-DgtPReljAgAuGaoLtQCm_E-UA_7j_TAGQ8kkV-mtjz4V" },
        };
    };
    pub const @"zquic-0.0.0-2rPds70RBACjqjpX56l2uBf_2-qCgIvU9X7sSKg8-lTM" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zquic-0.0.0-2rPds70RBACjqjpX56l2uBf_2-qCgIvU9X7sSKg8-lTM";
        pub const build_zig = @import("zquic-0.0.0-2rPds70RBACjqjpX56l2uBf_2-qCgIvU9X7sSKg8-lTM");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zquic", "zquic-0.0.0-2rPds70RBACjqjpX56l2uBf_2-qCgIvU9X7sSKg8-lTM" },
    .{ "zcrypto", "zcrypto-0.0.0-rgQAI8fbAwClmk2Me7c0fNLBtFWbukRh3ZgB2_IckfYz" },
    .{ "zqlite", "zqlite-0.4.0-0Cdu4lREBQAn6qz7Fwg5KDh8V7Kwc2JBEUxJjUckkP9V" },
};
