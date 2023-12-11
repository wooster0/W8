//! This standalone non-fallible terminal library abstracts everything related to the terminal and provides everything needed for
//! display, manipulation, and input events.
//!
//! This library is not intended for parallel or multi-threaded usage.
//! It is recommended to be used in a synchronized fashion.
//!
//! Reference: <https://invisible-island.net/xterm/ctlseqs/ctlseqs.html>.


const std = @import("std");
const os = std.os;
const linux = os.linux;

// TODO: get rid of this
pub const stdin = std.io.getStdIn();
pub const stdout = std.io.getStdOut();
pub const stderr = std.io.getStdErr();

var stdout_buffered_writer = std.io.BufferedWriter(4096, @TypeOf(stdout.writer())){ .unbuffered_writer = stdout.writer() };

pub fn print(comptime fmt: []const u8, args: anytype) void {
    stdout_buffered_writer.writer().print(fmt, args) catch {};
}

pub fn write(bytes: []const u8) void {
    stdout_buffered_writer.writer().writeAll(bytes) catch {};
}

pub fn flush() void {
    stdout_buffered_writer.flush() catch {};
}

const input_setup = struct {
    var old_termios: os.termios = undefined;

    fn init() void {
        old_termios = os.tcgetattr(stdin.handle) catch return;
        var new_termios = old_termios;

        // Make the terminal non-canonical so that we receive keypresses immediately
        // and disable echoing so that the keystroke is not printed to the terminal.
        new_termios.lflag &= ~(linux.ICANON | linux.ECHO);

        apply_termios(new_termios);
    }

    fn deinit() void {
        apply_termios(old_termios);
    }

    fn apply_termios(termios: os.termios) void {
        os.tcsetattr(stdin.handle, .FLUSH, termios) catch {};
    }
};

pub fn make_non_canonical() void {
    input_setup.init();
}
pub fn make_canonical() void {
    input_setup.deinit();
}

pub const cursor = struct {
/// Control Sequence Indicator.
const CSI = "\x1b[";

    /// Hides the cursor shape.
    pub fn hide() void {
        write(CSI ++ "?25l");
    }
    /// Show the cursor shape.
    pub fn show() void {
        write(CSI ++ "?25h");
    }

    /// Moves the cursor down by N amount of rows, to the first column.
    pub fn move_down(n: u16) void {
        print(CSI ++ "{}E", .{n});
    }
    /// Moves the cursor up by N amount of rows, to the first column.
    pub fn move_up(n: u16) void {
        print(CSI ++ "{}F", .{n});
    }
};
