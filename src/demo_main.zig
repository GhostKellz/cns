//! CNS DoQ Demo Main - showcasing zquic v0.8.2 features
const std = @import("std");
const cns_doq_demo = @import("cns_doq_demo.zig");

pub fn main() !void {
    try cns_doq_demo.main();
}