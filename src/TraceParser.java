import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Turns a raw `strace -f` line into a structured syscall, or reports that the line isn't one. */
final class TraceParser {

    /** A parsed syscall. {@code ret} is null when strace printed "&lt;unfinished ...&gt;". */
    record Syscall(int pid, String name, String args, Long ret, String errno, String errnoText) {
        boolean failed() { return ret != null && ret < 0; }
    }

    private static final Pattern HEAD =
            Pattern.compile("^(?:\\[pid\\s+(\\d+)\\]\\s+)?([a-z_][a-z0-9_]*)\\((.*)$");
    private static final Pattern TAIL =
            Pattern.compile("\\)\\s+=\\s+(-?\\d+|\\?|0x[0-9a-fA-F]+)(?:\\s+(E[A-Z0-9]+))?(?:\\s+\\(([^)]*)\\))?(?:\\s+<[\\d.]+>)?\\s*$");
    private static final Pattern QUOTED = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern INET =
            Pattern.compile("sa_family=AF_INET,\\s*sin_port=htons\\((\\d+)\\),\\s*sin_addr=inet_addr\\(\"([^\"]+)\"\\)");
    private static final Pattern INET6 =
            Pattern.compile("sa_family=AF_INET6,\\s*sin6_port=htons\\((\\d+)\\).*?inet_pton\\(AF_INET6,\\s*\"([^\"]+)\"");

    private static final Set<String> KNOWN = Set.of(
            "execve", "execveat",
            "open", "openat", "openat2", "creat",
            "stat", "lstat", "newfstatat", "fstatat64", "statx", "access", "faccessat", "faccessat2", "readlink", "readlinkat",
            "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat", "renameat2",
            "chmod", "fchmodat", "chown", "lchown", "fchownat", "symlink", "symlinkat", "link", "linkat", "truncate",
            "socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom");

    record NetTarget(String address, int port) {
        @Override public String toString() { return address + ":" + port; }
    }

    private TraceParser() {}

    /** True for syscalls the analyzer inspects; every other syscall is still parsed so it never leaks into program output. */
    static boolean isInspected(String name) { return KNOWN.contains(name); }

    /** strace's own bookkeeping lines: signals, exits, attach notices, diagnostics, continuations. */
    static boolean isMeta(String line) {
        return line.startsWith("+++") || line.startsWith("---") || line.startsWith("strace:")
                || line.matches("^(\\[pid\\s+\\d+\\]\\s+)?<\\.\\.\\.\\s+\\w+\\s+resumed>.*");
    }

    static Syscall parse(String line) {
        Matcher head = HEAD.matcher(line);
        if (!head.matches()) return null;
        String name = head.group(2);

        int pid = head.group(1) != null ? Integer.parseInt(head.group(1)) : 0;
        String rest = head.group(3);

        if (rest.contains("<unfinished ...>")) {
            return new Syscall(pid, name, rest.replace("<unfinished ...>", "").trim(), null, null, null);
        }

        Matcher tail = TAIL.matcher(rest);
        int start = -1;
        java.util.regex.MatchResult last = null;
        while (tail.find()) { start = tail.start(); last = tail.toMatchResult(); }
        if (last == null) return null;

        String args = rest.substring(0, start);
        String retStr = last.group(1);
        Long ret = null;
        try {
            ret = retStr.startsWith("0x") ? Long.decode(retStr) : (retStr.equals("?") ? null : Long.parseLong(retStr));
        } catch (NumberFormatException ignored) {}
        return new Syscall(pid, name, args, ret, last.group(2), last.group(3));
    }

    /** First quoted string in the argument list, i.e. the path for open/stat/mkdir/execve. */
    static String firstString(String args) {
        Matcher m = QUOTED.matcher(args);
        return m.find() ? unescape(m.group(1)) : null;
    }

    /** All quoted strings in the first [...] group, used to rebuild an execve command line. */
    static String argv(String args) {
        int open = args.indexOf('[');
        int close = args.indexOf(']', open + 1);
        if (open < 0 || close < 0) return "";
        List<String> parts = new ArrayList<>();
        Matcher m = QUOTED.matcher(args.substring(open, close + 1));
        while (m.find()) parts.add(unescape(m.group(1)));
        return String.join(" ", parts);
    }

    static NetTarget netTarget(String args) {
        Matcher m = INET.matcher(args);
        if (m.find()) return new NetTarget(m.group(2), Integer.parseInt(m.group(1)));
        m = INET6.matcher(args);
        if (m.find()) return new NetTarget(m.group(2), Integer.parseInt(m.group(1)));
        return null;
    }

    /** "AF_INET, SOCK_RAW, IPPROTO_ICMP" -> ["AF_INET", "SOCK_RAW"]. */
    static String[] socketKind(String args) {
        String[] p = args.split(",\\s*");
        if (p.length < 2) return new String[] {"", ""};
        return new String[] {p[0].trim(), p[1].trim().replaceAll("\\|.*", "")};
    }

    static boolean isLoopbackOrLocal(String ip) {
        return ip.startsWith("127.") || ip.equals("::1") || ip.equals("0.0.0.0") || ip.equals("::");
    }

    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\t", "\t");
    }
}
