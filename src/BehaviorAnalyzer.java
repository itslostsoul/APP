import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Consumes the sandbox's merged stdout/strace stream line by line. Each line is classified for the live
 * view (feed) and folded into an {@link Analysis} that carries the verdict (finish).
 *
 * The scoring is heuristic triage, not antivirus: it explains WHY a sample looks suspicious so an analyst
 * can decide what to look at next.
 */
final class BehaviorAnalyzer {

    private static final int MAX_LINES = 20_000;   // beyond this we keep draining but stop analysing (log-flood defence)
    private static final int MAX_RAW = 4_000;
    private static final int MAX_OUTPUT = 400;
    private static final int MAX_EVENTS = 400;

    private enum PathClass { NONE, SENSITIVE, PERSISTENCE, ESCAPE }

    private static final List<Pattern> SENSITIVE = patterns(
            "^/etc/(passwd|shadow|gshadow|sudoers|master\\.passwd)", "^/etc/sudoers\\.d/", "^/etc/security/",
            "/\\.ssh(/|$)", "/id_(rsa|dsa|ecdsa|ed25519)$", "/\\.aws/", "/\\.kube/", "/\\.docker/config\\.json$",
            "/\\.gnupg/", "/\\.netrc$", "/\\.git-credentials$", "/\\.(bash|zsh)_history$", "^/root(/|$)",
            "^/proc/(\\d+|self)/(environ|mem)$");
    private static final List<Pattern> ESCAPE = patterns(
            "docker\\.sock$", "release_agent$", "^/proc/sysrq-trigger$", "^/dev/(mem|kmem|port)$",
            "^/proc/1/(root|ns)");
    private static final List<Pattern> PERSISTENCE = patterns(
            "^/etc/(cron|crontab|init\\.d|inittab|rc\\d?\\.d|rc\\.local|profile|profile\\.d|systemd|ld\\.so\\.preload)",
            "^/var/spool/cron", "/\\.(bashrc|bash_profile|profile|zshrc)$", "authorized_keys$",
            "^/(usr/)?lib/systemd/");
    private static final Pattern WRITE_FLAGS = Pattern.compile("O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND");

    private static final String[] LOADER_PREFIXES = {
            "/lib/", "/lib64/", "/usr/lib/", "/usr/local/lib/", "/usr/lib64/", "/etc/ld-", "/etc/ld.so",
            "/proc/self/", "/proc/filesystems", "/proc/meminfo", "/proc/sys/", "/sys/", "/dev/null", "/dev/tty",
            "/dev/urandom", "/dev/random", "/dev/zero", "/etc/localtime", "/usr/share/zoneinfo", "/etc/nsswitch",
            "/etc/gai.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/services", "/etc/host.conf"};

    private static final Set<String> NET_TOOLS = Set.of(
            "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp", "tftp");

    private final Analysis a = new Analysis();

    // Live-view state
    private int totalLines;
    private int dropped;
    private int syscalls;
    private boolean telemetryProblem;
    private String rootExec;
    private final java.util.Map<String, Integer> eventIndex = new java.util.HashMap<>();

    // Evidence buckets used for scoring
    private final Set<String> childProcs = new LinkedHashSet<>();
    private final Set<String> netToolsUsed = new LinkedHashSet<>();
    private final Set<String> sensitiveAccess = new LinkedHashSet<>();
    private final Set<String> escapeAccess = new LinkedHashSet<>();
    private final Set<String> persistence = new LinkedHashSet<>();
    private final Set<String> hiddenPaths = new LinkedHashSet<>();
    private final Set<String> writesOutside = new LinkedHashSet<>();
    private final Set<String> tamper = new LinkedHashSet<>();
    private final Set<String> netDestinations = new LinkedHashSet<>();
    private final Set<String> listeners = new LinkedHashSet<>();
    private int netBlocked;

    /** Classifies one raw line for the live view and records it. Returns null for blank / over-limit lines. */
    synchronized LogEvent feed(String rawLine) {
        String line = rawLine.stripTrailing();
        if (line.isBlank()) return null;
        if (++totalLines > MAX_LINES) { dropped++; return null; }
        if (a.rawLog.size() < MAX_RAW) a.rawLog.add(truncate(line, 600));

        if (TraceParser.isMeta(line)) {
            if (line.startsWith("strace:") && !line.startsWith("strace: Process")) {
                telemetryProblem = true;
                return LogEvent.of(LogEvent.Kind.WARN, line);
            }
            return LogEvent.of(LogEvent.Kind.TRACE, line);
        }

        TraceParser.Syscall sc = TraceParser.parse(line);
        if (sc == null) {
            if (a.output.size() < MAX_OUTPUT) a.output.add(truncate(line, 400));
            return LogEvent.of(LogEvent.Kind.OUTPUT, line);
        }
        syscalls++;
        return handle(sc, line);
    }

    private LogEvent handle(TraceParser.Syscall sc, String line) {
        return switch (sc.name()) {
            case "execve", "execveat" -> onExec(sc, line);
            case "open", "openat", "openat2", "creat" -> onOpen(sc, line);
            case "stat", "lstat", "newfstatat", "fstatat64", "statx", "access", "faccessat", "faccessat2",
                 "readlink", "readlinkat" -> onProbe(sc, line);
            case "mkdir", "mkdirat" -> onMkdir(sc, line);
            case "unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2" -> onTamper(sc, line, "Removed or renamed");
            case "chmod", "fchmodat", "chown", "lchown", "fchownat" -> onTamper(sc, line, "Changed permissions on");
            case "socket" -> onSocket(sc, line);
            case "connect", "sendto", "sendmsg", "sendmmsg" -> onNetwork(sc, line);
            case "bind" -> onBind(sc, line);
            default -> trace(line);
        };
    }

    // ---------------------------------------------------------------- handlers

    private LogEvent onExec(TraceParser.Syscall sc, String line) {
        if (sc.ret() == null || sc.failed()) return trace(line);   // PATH search misses are noise
        String path = TraceParser.firstString(sc.args());
        if (path == null) return trace(line);
        String cmd = TraceParser.argv(sc.args());
        if (cmd.isBlank()) cmd = path;

        if (rootExec == null) {
            rootExec = path;
            return emit("process", "info", LogEvent.Kind.EXEC, baseName(path), "Payload entry point: " + cmd,
                    false, sc.pid(), "Payload started: " + cmd);
        }
        String base = baseName(path);
        boolean tool = NET_TOOLS.contains(base);
        if (tool) netToolsUsed.add(base);
        childProcs.add(cmd);
        a.iocProcesses.add(cmd);
        return emit("process", tool ? "high" : "low", LogEvent.Kind.EXEC, base, cmd, false, sc.pid(), "Spawned " + cmd);
    }

    private LogEvent onOpen(TraceParser.Syscall sc, String line) {
        String path = TraceParser.firstString(sc.args());
        if (path == null) return trace(line);
        boolean write = sc.name().equals("creat") || WRITE_FLAGS.matcher(sc.args()).find();
        boolean blocked = sc.failed() && !"ENOENT".equals(sc.errno());
        PathClass pc = classify(path);

        switch (pc) {
            case ESCAPE -> {
                escapeAccess.add(path);
                a.iocFiles.add(path);
                return emit("file", "critical", LogEvent.Kind.FILE, path, "Container-escape surface touched",
                        blocked, sc.pid(), "Touched " + path + suffix(sc));
            }
            case SENSITIVE -> {
                sensitiveAccess.add(path);
                a.iocFiles.add(path);
                return emit("file", "high", LogEvent.Kind.FILE, path,
                        write ? "Opened for writing" : "Opened for reading", blocked, sc.pid(),
                        (write ? "Write " : "Read ") + path + suffix(sc));
            }
            case PERSISTENCE -> {
                if (!write) return trace(line);
                persistence.add(path);
                a.iocFiles.add(path);
                return emit("persistence", "high", LogEvent.Kind.FILE, path, "Opened a startup / scheduler file for writing",
                        blocked, sc.pid(), "Persistence attempt: " + path + suffix(sc));
            }
            default -> { /* fall through to generic handling */ }
        }

        if (isLoaderNoise(path)) return trace(line);
        if (!write) return trace(line);

        if (isHidden(path)) {
            hiddenPaths.add(path);
            a.iocFiles.add(path);
            return emit("file", "high", LogEvent.Kind.FILE, path, "Created a hidden file", blocked, sc.pid(),
                    "Hidden file " + path + suffix(sc));
        }
        if (underTmp(path)) {
            if (path.startsWith("/tmp/payload")) return trace(line);    // the sandbox's own copy of the sample
            return emit("file", "low", LogEvent.Kind.FILE, path, "Wrote a file in /tmp", blocked, sc.pid(),
                    "Wrote " + path + suffix(sc));
        }
        writesOutside.add(path);
        a.iocFiles.add(path);
        return emit("file", "medium", LogEvent.Kind.FILE, path, "Wrote a file outside /tmp", blocked, sc.pid(),
                "Wrote " + path + suffix(sc));
    }

    private LogEvent onProbe(TraceParser.Syscall sc, String line) {
        String path = TraceParser.firstString(sc.args());
        // A failed stat is usually just the shell searching $PATH, so only successful probes are evidence.
        if (path == null || sc.failed() || sc.ret() == null) return trace(line);
        PathClass pc = classify(path);
        if (pc == PathClass.SENSITIVE) {
            sensitiveAccess.add(path);
            a.iocFiles.add(path);
            return emit("file", "high", LogEvent.Kind.FILE, path, "Inspected a credential / system file",
                    false, sc.pid(), "Inspected " + path);
        }
        if (pc == PathClass.ESCAPE) {
            escapeAccess.add(path);
            a.iocFiles.add(path);
            return emit("file", "critical", LogEvent.Kind.FILE, path, "Container-escape surface touched",
                    false, sc.pid(), "Touched " + path);
        }
        return trace(line);
    }

    private LogEvent onMkdir(TraceParser.Syscall sc, String line) {
        String path = TraceParser.firstString(sc.args());
        if (path == null || "EEXIST".equals(sc.errno())) return trace(line);   // already there, nothing was created
        boolean blocked = sc.failed();
        if (isHidden(path)) {
            hiddenPaths.add(path);
            a.iocFiles.add(path);
            return emit("file", "high", LogEvent.Kind.FILE, path, "Created a hidden directory", blocked, sc.pid(),
                    "Hidden directory " + path + suffix(sc));
        }
        if (underTmp(path)) {
            return emit("file", "low", LogEvent.Kind.FILE, path, "Created a directory in /tmp", blocked, sc.pid(),
                    "Created " + path + suffix(sc));
        }
        writesOutside.add(path);
        return emit("file", "medium", LogEvent.Kind.FILE, path, "Created a directory outside /tmp", blocked, sc.pid(),
                "Created " + path + suffix(sc));
    }

    private LogEvent onTamper(TraceParser.Syscall sc, String line, String verb) {
        String path = TraceParser.firstString(sc.args());
        if (path == null || underTmp(path) || isLoaderNoise(path)) return trace(line);
        tamper.add(path);
        a.iocFiles.add(path);
        return emit("file", "medium", LogEvent.Kind.FILE, path, verb + " a file outside /tmp",
                sc.failed(), sc.pid(), verb + " " + path + suffix(sc));
    }

    private LogEvent onSocket(TraceParser.Syscall sc, String line) {
        String[] kind = TraceParser.socketKind(sc.args());
        if (!kind[0].equals("AF_INET") && !kind[0].equals("AF_INET6")) return trace(line);
        String label = kind[0] + " " + kind[1];
        return emit("network", "low", LogEvent.Kind.NET, label, "Opened a network socket", sc.failed(), sc.pid(),
                "Opened " + label + " socket" + suffix(sc));
    }

    private LogEvent onNetwork(TraceParser.Syscall sc, String line) {
        TraceParser.NetTarget t = TraceParser.netTarget(sc.args());
        if (t == null || TraceParser.isLoopbackOrLocal(t.address())) return trace(line);
        boolean blocked = sc.failed() && !"EINPROGRESS".equals(sc.errno());
        boolean icmp = t.port() == 0;
        String verb = sc.name().equals("connect") ? "Connect to " : (icmp ? "ICMP to " : "Send to ");
        String label = icmp ? t.address() : t.toString();
        netDestinations.add(label);
        a.iocNetwork.add(label);
        if (blocked) netBlocked++;
        return emit("network", "high", LogEvent.Kind.NET, label,
                (icmp ? "ICMP echo / raw packet" : "Outbound connection") + " attempt", blocked, sc.pid(),
                verb + label + suffix(sc));
    }

    private LogEvent onBind(TraceParser.Syscall sc, String line) {
        TraceParser.NetTarget t = TraceParser.netTarget(sc.args());
        if (t == null || t.port() == 0) return trace(line);
        listeners.add(String.valueOf(t.port()));
        return emit("network", "medium", LogEvent.Kind.NET, "listen:" + t.port(), "Opened a listening port",
                sc.failed(), sc.pid(), "Listening on port " + t.port() + suffix(sc));
    }

    // ---------------------------------------------------------------- verdict

    /** Finalises the analysis once the container has exited (or been killed). */
    synchronized Analysis finish(SampleIntake.SampleInfo sample, String image, int exitCode, boolean timedOut,
                                 long durationMs, long timeoutSeconds) {
        a.sample = sample;
        a.image = image;
        a.exitCode = exitCode;
        a.timedOut = timedOut;
        a.durationMs = durationMs;
        a.timeoutSeconds = timeoutSeconds;
        a.id = idFor(sample);

        List<Analysis.Finding> f = a.findings;
        if (!escapeAccess.isEmpty())
            f.add(finding("escape", "critical", "Probed for a container escape", list(escapeAccess), 30));
        if (!persistence.isEmpty())
            f.add(finding("persistence", "high", "Tried to establish persistence", list(persistence), 25));
        if (!sensitiveAccess.isEmpty())
            f.add(finding("sensitive-files", "high", "Accessed credential or system files", list(sensitiveAccess), 25));
        if (!netDestinations.isEmpty()) {
            String tail = netBlocked >= netDestinations.size() ? " (all blocked, the sandbox has no network)" : "";
            f.add(finding("network", "high", "Tried to reach the network", list(netDestinations) + tail, 20));
        }
        if (!netToolsUsed.isEmpty())
            f.add(finding("net-tools", "high", "Ran download or remote-access tools", list(netToolsUsed), 20));
        if (!listeners.isEmpty())
            f.add(finding("listener", "medium", "Opened a listening port", "Port " + list(listeners), 15));
        if (!hiddenPaths.isEmpty())
            f.add(finding("hidden-files", "medium", "Created hidden files or directories", list(hiddenPaths), 15));
        if (!writesOutside.isEmpty())
            f.add(finding("fs-write", "medium", "Wrote outside /tmp", list(writesOutside), 10));
        if (!tamper.isEmpty())
            f.add(finding("fs-tamper", "medium", "Deleted, renamed or re-permissioned files", list(tamper), 10));
        if (!childProcs.isEmpty()) {
            int pts = Math.min(2, childProcs.size()) * 5;
            f.add(finding("children", "low", "Spawned " + childProcs.size() + " child process"
                    + (childProcs.size() == 1 ? "" : "es"), list(childProcs), pts));
        }
        if (timedOut)
            f.add(finding("timeout", "medium", "Ran past the time limit",
                    "Killed after " + timeoutSeconds + " s. Endless loops and sleeps are a common sandbox-evasion trick.", 15));
        else if (exitCode == 137)
            f.add(finding("killed", "low", "Killed by the kernel",
                    "Exit code 137 usually means the 512 MB memory limit was hit.", 5));
        else if (exitCode != 0)
            f.add(finding("exit-code", "info", "Exited with code " + exitCode, "Non-zero exit status.", 5));

        int total = f.stream().mapToInt(Analysis.Finding::points).sum();
        a.score = Math.min(100, total);
        a.level = Analysis.Level.forScore(a.score);
        f.sort((x, y) -> Integer.compare(y.points(), x.points()));

        if (syscalls == 0) {
            a.notes.add("No system calls were captured, so this verdict rests on program output and exit status only.");
        }
        if (telemetryProblem) {
            a.notes.add("strace reported a problem. The sandbox may have restricted tracing, so behaviour could be under-reported.");
        }
        if (dropped > 0) {
            a.notes.add(dropped + " log lines beyond the " + MAX_LINES + "-line cap were discarded (possible log-flood attempt).");
        }
        return a;
    }

    /** Builds an Analysis for a failure that has nothing to do with the sample (Docker down, image build failed...). */
    static Analysis failed(SampleIntake.SampleInfo sample, String message) {
        Analysis a = new Analysis();
        a.sample = sample;
        a.failed = true;
        a.error = message;
        a.level = Analysis.Level.INCONCLUSIVE;
        a.id = idFor(sample);
        return a;
    }

    // ---------------------------------------------------------------- helpers

    private LogEvent emit(String type, String severity, LogEvent.Kind kind, String label, String detail,
                            boolean blocked, int pid, String text) {
        String key = type + "|" + label;
        Analysis.Event ev = new Analysis.Event(type, severity, label, detail, blocked, pid);
        Integer at = eventIndex.get(key);
        if (at != null) {
            // Same target seen again: keep the stronger observation ("opened" beats "inspected") but don't duplicate it.
            Analysis.Event old = a.events.get(at);
            if (rank(ev) > rank(old)) {
                a.events.set(at, ev);
                return LogEvent.of(kind, text);
            }
            return LogEvent.of(LogEvent.Kind.TRACE, text);
        }
        if (a.events.size() >= MAX_EVENTS) return LogEvent.of(LogEvent.Kind.TRACE, text);
        eventIndex.put(key, a.events.size());
        a.events.add(ev);
        return LogEvent.of(kind, text);
    }

    private static int rank(Analysis.Event e) {
        return e.detail().startsWith("Opened") ? 2 : 1;
    }

    private static LogEvent trace(String line) {
        return LogEvent.of(LogEvent.Kind.TRACE, line);
    }

    private static String suffix(TraceParser.Syscall sc) {
        if (!sc.failed() || sc.errnoText() == null) return "";
        if ("EINPROGRESS".equals(sc.errno()) || "EEXIST".equals(sc.errno())) return "";
        return " (blocked: " + sc.errnoText().toLowerCase(Locale.ROOT) + ")";
    }

    private static Analysis.Finding finding(String id, String sev, String title, String detail, int pts) {
        return new Analysis.Finding(id, sev, title, detail, pts);
    }

    private static String list(Set<String> items) {
        List<String> l = new ArrayList<>(items);
        String head = String.join(", ", l.subList(0, Math.min(3, l.size())));
        return l.size() > 3 ? head + " and " + (l.size() - 3) + " more" : head;
    }

    private static PathClass classify(String path) {
        for (Pattern p : ESCAPE) if (p.matcher(path).find()) return PathClass.ESCAPE;
        for (Pattern p : SENSITIVE) if (p.matcher(path).find()) return PathClass.SENSITIVE;
        for (Pattern p : PERSISTENCE) if (p.matcher(path).find()) return PathClass.PERSISTENCE;
        return PathClass.NONE;
    }

    private static boolean isLoaderNoise(String path) {
        for (String prefix : LOADER_PREFIXES) if (path.startsWith(prefix)) return true;
        return false;
    }

    private static boolean underTmp(String path) {
        return path.equals("/tmp") || path.startsWith("/tmp/");
    }

    private static boolean isHidden(String path) {
        for (String seg : path.split("/")) {
            if (seg.length() > 1 && seg.charAt(0) == '.' && !seg.equals("..")) return true;
        }
        return false;
    }

    private static String baseName(String path) {
        int i = path.lastIndexOf('/');
        return i >= 0 ? path.substring(i + 1) : path;
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private static List<Pattern> patterns(String... regex) {
        List<Pattern> out = new ArrayList<>();
        for (String r : regex) out.add(Pattern.compile(r));
        return out;
    }

    private static String idFor(SampleIntake.SampleInfo s) {
        String stamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        return stamp + "-" + (s != null ? s.shortHash() : "unknown");
    }
}
